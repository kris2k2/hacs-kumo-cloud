"""Config flow for the Kumo Cloud integration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import voluptuous as vol

from homeassistant import config_entries

from .const import DOMAIN

if TYPE_CHECKING:
    from homeassistant.data_entry_flow import FlowResult
else:  # pragma: no cover - typing fallback for older Home Assistant versions
    FlowResult = Any

DATA_SCHEMA = vol.Schema(
    {
        vol.Required("username"): str,
        vol.Required("password"): str,
    }
)


class ConfigFlow(config_entries.ConfigFlow):
    """Handle a config flow for Kumo Cloud."""

    VERSION = 1
    domain = DOMAIN

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle the initial step where the user enters credentials."""
        errors: dict[str, str] = {}

        if user_input is not None:
            await self.async_set_unique_id(user_input["username"].lower())
            self._abort_if_unique_id_configured()

            return self.async_create_entry(
                title=user_input["username"],
                data={
                    "username": user_input["username"],
                    "password": user_input["password"],
                },
            )

        return self.async_show_form(
            step_id="user",
            data_schema=DATA_SCHEMA,
            errors=errors,
        )

if hasattr(config_entries, "HANDLERS"):
    try:
        config_entries.HANDLERS.register(DOMAIN)(ConfigFlow)
    except ValueError:
        # Handler already registered on this core version.
        pass
