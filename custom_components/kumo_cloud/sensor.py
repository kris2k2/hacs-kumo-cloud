"""Diagnostic sensors for the Kumo Cloud integration."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .manager import AuthenticationState, KumoCloudManager, WebsocketState


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Kumo Cloud sensors from a config entry."""

    data = hass.data[DOMAIN][entry.entry_id]
    manager: KumoCloudManager = data["manager"]

    sensors: list[SensorEntity] = [
        KumoCloudAuthenticationSensor(manager, entry),
        KumoCloudWebsocketSensor(manager, entry),
    ]

    async_add_entities(sensors)


class KumoCloudBaseSensor(SensorEntity):
    """Base class for Kumo Cloud diagnostic sensors."""

    _attr_should_poll = False
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, manager: KumoCloudManager, entry: ConfigEntry, name: str, unique_suffix: str) -> None:
        """Initialize the base sensor."""

        self._manager = manager
        self._entry = entry
        self._attr_name = f"{entry.title} {name}" if entry.title else name
        self._attr_unique_id = f"{entry.entry_id}_{unique_suffix}"
        self._remove_listener: Callable[[], None] | None = None

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            manufacturer="Mitsubishi Electric",
            name=entry.title,
        )

    async def async_added_to_hass(self) -> None:
        """Register callbacks when added to Home Assistant."""

        await super().async_added_to_hass()

        def _handle_update() -> None:
            self.async_write_ha_state()

        remove = self._manager.async_add_listener(_handle_update)
        self._remove_listener = remove
        self.async_on_remove(remove)

    async def async_will_remove_from_hass(self) -> None:
        """Handle removal from Home Assistant."""

        await super().async_will_remove_from_hass()
        if self._remove_listener is not None:
            self._remove_listener()
            self._remove_listener = None

    @staticmethod
    def _format_datetime(value: datetime | None) -> str | None:
        """Format datetimes for state attributes."""

        if value is None:
            return None

        return dt_util.as_local(value).isoformat()


class KumoCloudAuthenticationSensor(KumoCloudBaseSensor):
    """Sensor reporting authentication state."""

    _attr_icon = "mdi:account-key"

    def __init__(self, manager: KumoCloudManager, entry: ConfigEntry) -> None:
        """Initialize the sensor."""

        super().__init__(manager, entry, "Authentication", "auth_state")

    @property
    def native_value(self) -> str:
        """Return the current authentication state."""

        state = self._manager.auth_state
        if isinstance(state, AuthenticationState):
            return state.value
        return str(state)

    @property
    def extra_state_attributes(self) -> dict[str, str | int | None]:
        """Return additional diagnostic information."""

        expires_at = self._manager.token_expires_at

        attrs: dict[str, str | int | None] = {
            "last_success_at": self._format_datetime(self._manager.auth_last_success),
            "last_failure_at": self._format_datetime(self._manager.auth_last_failure),
            "token_expires_at": self._format_datetime(expires_at),
        }

        if self._manager.auth_error:
            attrs["last_error"] = self._manager.auth_error

        if expires_at is not None:
            remaining = int((expires_at - dt_util.utcnow()).total_seconds())
            attrs["token_expires_in"] = max(remaining, 0)

        return attrs


class KumoCloudWebsocketSensor(KumoCloudBaseSensor):
    """Sensor reporting websocket connection state."""

    _attr_icon = "mdi:lan-connect"

    def __init__(self, manager: KumoCloudManager, entry: ConfigEntry) -> None:
        """Initialize the sensor."""

        super().__init__(manager, entry, "Websocket", "websocket_state")

    @property
    def native_value(self) -> str:
        """Return the current websocket state."""

        state = self._manager.websocket_state
        if isinstance(state, WebsocketState):
            return state.value
        return str(state)

    @property
    def extra_state_attributes(self) -> dict[str, str | float | None]:
        """Return additional diagnostic information about the websocket."""

        attrs: dict[str, str | float | None] = {
            "last_connected_at": self._format_datetime(self._manager.websocket_last_connected),
            "last_failure_at": self._format_datetime(self._manager.websocket_last_failure),
            "session_id": self._manager.websocket_sid,
            "ping_interval": self._manager.websocket_ping_interval,
            "ping_timeout": self._manager.websocket_ping_timeout,
        }

        if self._manager.websocket_error:
            attrs["last_error"] = self._manager.websocket_error

        return attrs
