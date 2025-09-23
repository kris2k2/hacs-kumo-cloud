"""The Kumo Cloud integration for Home Assistant."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN, PLATFORMS


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the Kumo Cloud component."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Kumo Cloud from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    hass.data[DOMAIN][entry.entry_id] = {
        "username": entry.data["username"],
        "password": entry.data["password"],
        # Placeholders for future API clients and metadata.
        "client": None,
    }

    if PLATFORMS:
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a Kumo Cloud config entry."""
    if PLATFORMS:
        await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN].pop(entry.entry_id, None)

    return True
