"""Config flow for the Kumo Cloud integration."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import voluptuous as vol
from aiohttp import ClientError, ClientResponseError, ClientTimeout

from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import API_BASE_URL, APP_VERSION, DOMAIN, LOGIN_ENDPOINT, PREFERRED_HEADERS

_LOGGER = logging.getLogger(__name__)


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Kumo Cloud."""

    VERSION = 1
    domain = DOMAIN

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle the initial step where the user enters credentials."""
        errors: dict[str, str] = {}

        if user_input is not None:
            username = user_input[CONF_USERNAME]
            password = user_input[CONF_PASSWORD]

            try:
                await self._async_validate_credentials(username, password)
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except Exception:  # pragma: no cover - defensive logging
                _LOGGER.exception("Unexpected error validating credentials")
                errors["base"] = "unknown"
            else:
                await self.async_set_unique_id(username.lower())
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=username,
                    data={
                        CONF_USERNAME: username,
                        CONF_PASSWORD: password,
                    },
                )

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME): str,
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )

    async def _async_validate_credentials(self, username: str, password: str) -> None:
        """Validate the provided credentials against the Kumo Cloud service."""

        session = async_get_clientsession(self.hass)
        payload = {
            "username": username,
            "password": password,
            "appVersion": APP_VERSION,
        }

        try:
            async with session.post(
                f"{API_BASE_URL}{LOGIN_ENDPOINT}",
                json=payload,
                headers=PREFERRED_HEADERS,
                timeout=ClientTimeout(total=30),
            ) as response:
                response.raise_for_status()
                data = await response.json()
        except ClientResponseError as err:
            if err.status in (401, 403):
                raise InvalidAuth from err
            raise CannotConnect from err
        except (ClientError, asyncio.TimeoutError) as err:
            raise CannotConnect from err
        except json.JSONDecodeError as err:
            raise CannotConnect from err

        token = data.get("token", {})
        access = token.get("access")

        if not access:
            raise CannotConnect


class InvalidAuth(HomeAssistantError):
    """Error to indicate invalid authentication."""


class CannotConnect(HomeAssistantError):
    """Error to indicate connection failure."""
