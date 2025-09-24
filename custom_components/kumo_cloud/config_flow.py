"""Config flow for the Kumo Cloud integration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Type

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


async def _async_step_user(
    self, user_input: dict[str, Any] | None = None
) -> FlowResult:
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


class _BaseConfigFlow(config_entries.ConfigFlow):
    """Shared implementation for the Kumo Cloud config flow."""

    VERSION = 1
    domain = DOMAIN
    async_step_user = _async_step_user


try:
    class ConfigFlow(_BaseConfigFlow, domain=DOMAIN):
        """Handle a config flow for Kumo Cloud."""

        pass
except TypeError:
    class ConfigFlow(_BaseConfigFlow):
        """Handle a config flow for Kumo Cloud."""

        pass


def _register_legacy_flow_handler(flow_cls: Type[config_entries.ConfigFlow]) -> None:
    """Register the flow handler on Home Assistant cores without auto discovery."""

    handlers = getattr(config_entries, "HANDLERS", None)
    if handlers is None:
        return

    register = getattr(handlers, "register", None)
    if callable(register):
        try:
            register(DOMAIN)(flow_cls)
        except ValueError:
            # Handler already registered on this core version.
            pass
        return

    try:
        handlers[DOMAIN] = flow_cls
    except Exception:  # pragma: no cover - defensive fallback for legacy registries
        pass


_register_legacy_flow_handler(ConfigFlow)
