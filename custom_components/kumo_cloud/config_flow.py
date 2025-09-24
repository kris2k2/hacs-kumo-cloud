"""Config flow for the Kumo Cloud integration."""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import TYPE_CHECKING, Any, cast

from homeassistant import config_entries

from .const import DOMAIN

if TYPE_CHECKING:
    from homeassistant.data_entry_flow import FlowResult
    from voluptuous import Schema as VolSchema
else:  # pragma: no cover - typing fallback for older Home Assistant versions
    FlowResult = Any
    VolSchema = Any


_VOLUPTUOUS: ModuleType | None = None


class ConfigFlow(config_entries.ConfigFlow):
    """Handle a config flow for Kumo Cloud."""

    VERSION = 1
    domain = DOMAIN

    async def _async_get_data_schema(self) -> VolSchema:
        """Return the data schema, importing voluptuous lazily."""

        global _VOLUPTUOUS

        if _VOLUPTUOUS is None:
            _VOLUPTUOUS = cast(
                ModuleType,
                await self.hass.async_add_executor_job(
                    importlib.import_module, "voluptuous"
                ),
            )

        vol = _VOLUPTUOUS

        return vol.Schema(
            {
                vol.Required("username"): str,
                vol.Required("password"): str,
            }
        )

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

        data_schema = await self._async_get_data_schema()

        return self.async_show_form(
            step_id="user",
            data_schema=data_schema,
            errors=errors,
        )

if hasattr(config_entries, "HANDLERS"):
    try:
        config_entries.HANDLERS.register(DOMAIN)(ConfigFlow)
    except ValueError:
        # Handler already registered on this core version.
        pass
