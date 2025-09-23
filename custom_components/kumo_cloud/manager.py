"""Runtime manager handling authentication and websocket connectivity."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable
import contextlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import json
import logging
import time
from typing import Any

import aiohttp
from aiohttp import (
    ClientError,
    ClientResponseError,
    ClientSession,
    ClientTimeout,
    ClientWebSocketResponse,
    WSMsgType,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import CALLBACK_TYPE
from homeassistant.util import dt as dt_util

from .const import (
    API_BASE_URL,
    APP_VERSION,
    LOGIN_ENDPOINT,
    PREFERRED_HEADERS,
    SOCKET_IO_BASE_URL,
    SOCKET_IO_WEBSOCKET_URL,
    TOKEN_REFRESH_LEEWAY,
    WEBSOCKET_RETRY_DELAY,
)

LOGGER = logging.getLogger(__name__)


class AuthenticationState(str, Enum):
    """Enumeration of authentication states."""

    IDLE = "idle"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED = "authenticated"
    ERROR = "error"


class WebsocketState(str, Enum):
    """Enumeration of websocket connection states."""

    IDLE = "idle"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"


@dataclass(slots=True)
class EngineIOHandshake:
    """Details from the Engine.IO handshake response."""

    sid: str
    ping_interval: float
    ping_timeout: float
    upgrades: list[str]
    raw: dict[str, Any]


class KumoCloudManager:
    """Coordinate authentication and websocket state for Kumo Cloud."""

    def __init__(self, hass: HomeAssistant, entry_id: str, username: str, password: str) -> None:
        """Initialize the manager."""

        self._hass = hass
        self._entry_id = entry_id
        self._username = username
        self._password = password
        self._session: ClientSession = async_get_clientsession(hass)

        self._auth_state: AuthenticationState = AuthenticationState.IDLE
        self._auth_error: str | None = None
        self._auth_last_success: datetime | None = None
        self._auth_last_failure: datetime | None = None
        self._token_expires_at: datetime | None = None

        self._access_token: str | None = None
        self._refresh_token: str | None = None

        self._websocket_state: WebsocketState = WebsocketState.IDLE
        self._websocket_error: str | None = None
        self._websocket_last_connected: datetime | None = None
        self._websocket_last_failure: datetime | None = None
        self._websocket_sid: str | None = None
        self._websocket_ping_interval: float | None = None
        self._websocket_ping_timeout: float | None = None

        self._listeners: set[CALLBACK_TYPE] = set()

        self._refresh_task: asyncio.Task[None] | None = None
        self._websocket_task: asyncio.Task[None] | None = None
        self._ping_task: asyncio.Task[None] | None = None
        self._current_ws: ClientWebSocketResponse | None = None

        self._running = False
        self._auth_lock = asyncio.Lock()

    async def async_start(self) -> None:
        """Start authentication management and websocket handling."""

        if self._running:
            return

        self._running = True
        await self._async_ensure_authenticated()

        self._refresh_task = self._hass.loop.create_task(self._refresh_loop())
        self._websocket_task = self._hass.loop.create_task(self._websocket_loop())

    async def async_stop(self) -> None:
        """Stop background tasks and close websocket."""

        if not self._running:
            return

        self._running = False

        for task in (self._refresh_task, self._websocket_task, self._ping_task):
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

        self._refresh_task = None
        self._websocket_task = None
        self._ping_task = None

        if self._current_ws is not None and not self._current_ws.closed:
            with contextlib.suppress(asyncio.CancelledError, ClientError):
                await self._current_ws.close()

        self._current_ws = None

        self._set_websocket_state(WebsocketState.IDLE)
        self._set_auth_state(AuthenticationState.IDLE)

    async def _refresh_loop(self) -> None:
        """Periodically ensure the authentication token is valid."""

        try:
            while self._running:
                wait_seconds = self._seconds_until_refresh()
                await asyncio.sleep(wait_seconds)
                await self._async_ensure_authenticated()
        except asyncio.CancelledError:  # pragma: no cover - task cancelled at shutdown
            raise
        except Exception:  # pragma: no cover - defensive logging
            LOGGER.exception("Unexpected error in refresh loop")

    async def _websocket_loop(self) -> None:
        """Maintain the websocket connection with automatic retries."""

        try:
            while self._running:
                if not self._access_token:
                    self._set_websocket_state(
                        WebsocketState.DISCONNECTED,
                        error="no access token available",
                    )
                    await asyncio.sleep(WEBSOCKET_RETRY_DELAY.total_seconds())
                    continue

                try:
                    await self._async_run_websocket()
                except asyncio.CancelledError:
                    raise
                except ClientResponseError as err:
                    details = f": {err.message}" if err.message else ""
                    message = f"Websocket error {err.status}{details}"
                    LOGGER.warning(message)
                    if err.status == 401:
                        self._clear_tokens()
                    self._set_websocket_state(WebsocketState.ERROR, error=message)
                except Exception as err:  # pragma: no cover - defensive logging
                    LOGGER.warning("Unexpected websocket failure: %s", err, exc_info=True)
                    self._set_websocket_state(WebsocketState.ERROR, error=str(err))

                if not self._running:
                    break

                await asyncio.sleep(WEBSOCKET_RETRY_DELAY.total_seconds())
        except asyncio.CancelledError:  # pragma: no cover - task cancelled at shutdown
            raise

    async def _async_run_websocket(self) -> None:
        """Open the websocket connection until it closes."""

        handshake = await self._async_engineio_handshake()

        if "websocket" not in handshake.upgrades:
            raise RuntimeError("Server does not allow websocket upgrade")

        await self._async_establish_websocket(handshake)

    async def _async_engineio_handshake(self) -> EngineIOHandshake:
        """Perform the initial polling request to obtain an Engine.IO session id."""

        self._set_websocket_state(WebsocketState.CONNECTING)

        self._websocket_sid = None
        self._websocket_ping_interval = None
        self._websocket_ping_timeout = None

        token = self._access_token
        if not token:
            raise RuntimeError("Access token unavailable for websocket handshake")

        params = {
            "EIO": "4",
            "transport": "polling",
            "t": f"{int(time.time() * 1000)}",
        }

        headers = {**PREFERRED_HEADERS, "Authorization": f"Bearer {token}", "Accept": "*/*"}

        timeout = ClientTimeout(total=30)

        async with self._session.get(
            SOCKET_IO_BASE_URL,
            params=params,
            headers=headers,
            timeout=timeout,
        ) as response:
            response.raise_for_status()
            payload = await response.text()

        if not payload.startswith("0"):
            raise RuntimeError("Unexpected handshake payload")

        try:
            data = json.loads(payload[1:])
        except json.JSONDecodeError as err:
            raise RuntimeError("Failed to decode handshake payload") from err

        sid = data["sid"]
        ping_interval = float(data.get("pingInterval", 25000)) / 1000.0
        ping_timeout = float(data.get("pingTimeout", 20000)) / 1000.0
        upgrades = list(data.get("upgrades", []))

        self._websocket_sid = sid
        self._websocket_ping_interval = ping_interval
        self._websocket_ping_timeout = ping_timeout

        return EngineIOHandshake(sid=sid, ping_interval=ping_interval, ping_timeout=ping_timeout, upgrades=upgrades, raw=data)

    async def _async_establish_websocket(self, handshake: EngineIOHandshake) -> None:
        """Upgrade the Engine.IO session to a websocket connection."""

        params = {
            "EIO": "4",
            "transport": "websocket",
            "sid": handshake.sid,
        }

        token = self._access_token
        if not token:
            raise RuntimeError("Access token unavailable for websocket upgrade")

        headers = {**PREFERRED_HEADERS, "Authorization": f"Bearer {token}", "Accept": "*/*"}

        timeout = ClientTimeout(total=30)

        ws = await self._session.ws_connect(
            SOCKET_IO_WEBSOCKET_URL,
            params=params,
            headers=headers,
            timeout=timeout,
            heartbeat=None,
        )

        self._current_ws = ws

        try:
            await ws.send_str("2probe")
            probe_response = await asyncio.wait_for(ws.receive(), timeout=handshake.ping_timeout)

            if probe_response.type != WSMsgType.TEXT or probe_response.data != "3probe":
                raise RuntimeError("Websocket probe handshake failed")

            await ws.send_str("5")

            self._set_websocket_state(WebsocketState.CONNECTED)
            self._websocket_last_connected = dt_util.utcnow()
            self._websocket_last_failure = None

            self._ping_task = self._hass.loop.create_task(self._async_ping(ws, handshake.ping_interval))

            async for message in ws:
                if message.type == WSMsgType.TEXT:
                    data = message.data
                    if data == "3":
                        continue
                    if data == "2":
                        await ws.send_str("3")
                        continue
                    if data == "41":
                        break
                elif message.type in (WSMsgType.CLOSE, WSMsgType.CLOSED):
                    break
                elif message.type == WSMsgType.ERROR:
                    raise message.exception() or RuntimeError("Websocket error")
        finally:
            if self._ping_task is not None:
                self._ping_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self._ping_task
                self._ping_task = None

            self._current_ws = None

            if self._websocket_state == WebsocketState.CONNECTED:
                self._set_websocket_state(WebsocketState.DISCONNECTED)

    async def _async_ping(self, ws: ClientWebSocketResponse, interval: float) -> None:
        """Send periodic Engine.IO ping frames."""

        delay = max(interval * 0.9, 1.0)

        try:
            while True:
                await asyncio.sleep(delay)
                if ws.closed:
                    break
                await ws.send_str("2")
        except asyncio.CancelledError:  # pragma: no cover - routine cancellation
            raise
        except Exception as err:  # pragma: no cover - defensive logging
            LOGGER.debug("Ping loop error: %s", err)

    async def _async_ensure_authenticated(self) -> None:
        """Ensure that a valid access token is available."""

        async with self._auth_lock:
            if self._access_token and not self._token_needs_refresh():
                return

            await self._async_login_locked()

    async def _async_login_locked(self) -> None:
        """Perform the login request and update stored credentials."""

        self._set_auth_state(AuthenticationState.AUTHENTICATING)

        payload = {
            "username": self._username,
            "password": self._password,
            "appVersion": APP_VERSION,
        }

        timeout = ClientTimeout(total=30)

        try:
            async with self._session.post(
                f"{API_BASE_URL}{LOGIN_ENDPOINT}",
                json=payload,
                headers=PREFERRED_HEADERS,
                timeout=timeout,
            ) as response:
                response.raise_for_status()
                data = await response.json()
        except ClientResponseError as err:
            details = f": {err.message}" if err.message else ""
            message = f"Login failed ({err.status}){details}"
            LOGGER.warning(message)
            self._clear_tokens()
            self._auth_last_failure = dt_util.utcnow()
            self._set_auth_state(AuthenticationState.ERROR, error=message)
            return
        except (ClientError, asyncio.TimeoutError) as err:
            message = f"Login request error: {err}"
            LOGGER.warning(message)
            self._clear_tokens()
            self._auth_last_failure = dt_util.utcnow()
            self._set_auth_state(AuthenticationState.ERROR, error=message)
            return
        except json.JSONDecodeError as err:
            message = "Invalid response during login"
            LOGGER.warning(message)
            self._clear_tokens()
            self._auth_last_failure = dt_util.utcnow()
            self._set_auth_state(AuthenticationState.ERROR, error=message)
            return

        token = data.get("token", {})
        access = token.get("access")
        refresh = token.get("refresh")

        if not access:
            message = "Login response missing access token"
            LOGGER.warning(message)
            self._clear_tokens()
            self._auth_last_failure = dt_util.utcnow()
            self._set_auth_state(AuthenticationState.ERROR, error=message)
            return

        self._access_token = access
        self._refresh_token = refresh
        self._token_expires_at = _decode_jwt_expiration(access)
        self._auth_last_success = dt_util.utcnow()
        self._auth_last_failure = None
        self._set_auth_state(AuthenticationState.AUTHENTICATED)

        if self._current_ws is not None and not self._current_ws.closed:
            with contextlib.suppress(Exception):
                await self._current_ws.close(code=aiohttp.WSCloseCode.GOING_AWAY, message=b"token refreshed")

    def _seconds_until_refresh(self) -> float:
        """Determine the delay before the next authentication refresh."""

        if not self._access_token or not self._token_expires_at:
            return max(WEBSOCKET_RETRY_DELAY.total_seconds(), 15.0)

        refresh_at = self._token_expires_at - TOKEN_REFRESH_LEEWAY
        now = dt_util.utcnow()

        if refresh_at <= now:
            return 0.0

        delta: timedelta = refresh_at - now
        return max(delta.total_seconds(), 0.0)

    def _token_needs_refresh(self) -> bool:
        """Return True if the current access token is expired or nearing expiry."""

        if not self._access_token or not self._token_expires_at:
            return True

        refresh_at = self._token_expires_at - TOKEN_REFRESH_LEEWAY
        return refresh_at <= dt_util.utcnow()

    def _clear_tokens(self) -> None:
        """Reset stored authentication tokens."""

        self._access_token = None
        self._refresh_token = None
        self._token_expires_at = None

    @callback
    def async_add_listener(self, listener: Callable[[], None]) -> CALLBACK_TYPE:
        """Register a callback for state updates."""

        self._listeners.add(listener)

        def _remove() -> None:
            self._listeners.discard(listener)

        return _remove

    @callback
    def _async_notify_listeners(self) -> None:
        """Notify listeners that state has changed."""

        for listener in list(self._listeners):
            listener()

    def _set_auth_state(self, state: AuthenticationState, *, error: str | None = None) -> None:
        """Update the authentication state and notify if it changed."""

        if self._auth_state == state and self._auth_error == error:
            return

        self._auth_state = state
        self._auth_error = error
        self._async_notify_listeners()

    def _set_websocket_state(self, state: WebsocketState, *, error: str | None = None) -> None:
        """Update the websocket state and notify listeners if needed."""

        if state == WebsocketState.ERROR:
            self._websocket_last_failure = dt_util.utcnow()

        if self._websocket_state == state and self._websocket_error == error:
            return

        self._websocket_state = state
        self._websocket_error = error
        self._async_notify_listeners()

    @property
    def auth_state(self) -> AuthenticationState:
        """Return the current authentication state."""

        return self._auth_state

    @property
    def auth_error(self) -> str | None:
        """Return the last authentication error message."""

        return self._auth_error

    @property
    def auth_last_success(self) -> datetime | None:
        """Return the timestamp of the last successful authentication."""

        return self._auth_last_success

    @property
    def auth_last_failure(self) -> datetime | None:
        """Return the timestamp of the last authentication failure."""

        return self._auth_last_failure

    @property
    def token_expires_at(self) -> datetime | None:
        """Return the expiration timestamp for the access token."""

        return self._token_expires_at

    @property
    def websocket_state(self) -> WebsocketState:
        """Return the websocket connection state."""

        return self._websocket_state

    @property
    def websocket_error(self) -> str | None:
        """Return the last websocket error."""

        return self._websocket_error

    @property
    def websocket_last_connected(self) -> datetime | None:
        """Return the timestamp of the last successful websocket connection."""

        return self._websocket_last_connected

    @property
    def websocket_last_failure(self) -> datetime | None:
        """Return the timestamp of the last websocket failure."""

        return self._websocket_last_failure

    @property
    def websocket_sid(self) -> str | None:
        """Return the current Engine.IO session identifier."""

        return self._websocket_sid

    @property
    def websocket_ping_interval(self) -> float | None:
        """Return the negotiated ping interval in seconds."""

        return self._websocket_ping_interval

    @property
    def websocket_ping_timeout(self) -> float | None:
        """Return the negotiated ping timeout in seconds."""

        return self._websocket_ping_timeout


def _decode_jwt_expiration(token: str) -> datetime | None:
    """Decode a JWT access token and extract the expiration timestamp."""

    parts = token.split(".")
    if len(parts) < 2:
        return None

    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        decoded = base64.urlsafe_b64decode((payload_b64 + padding).encode("utf-8"))
        payload = json.loads(decoded.decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None

    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        try:
            return dt_util.utc_from_timestamp(float(exp))
        except (OverflowError, OSError, ValueError):
            return None

    return None
