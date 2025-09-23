"""The Kumo Cloud integration for Home Assistant."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN, PLATFORMS
from .manager import KumoCloudManager


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the Kumo Cloud component."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Kumo Cloud from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    manager = KumoCloudManager(
        hass,
        entry.entry_id,
        entry.data["username"],
        entry.data["password"],
    )

    hass.data[DOMAIN][entry.entry_id] = {
        "manager": manager,
    }

    try:
        await manager.async_start()
    except Exception:  # pragma: no cover - defensive cleanup
        await manager.async_stop()
        hass.data[DOMAIN].pop(entry.entry_id, None)
        raise

    if PLATFORMS:
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a Kumo Cloud config entry."""
    hass.data.setdefault(DOMAIN, {})

    stored = hass.data[DOMAIN].get(entry.entry_id)
    manager: KumoCloudManager | None = None
    if stored is not None:
        manager = stored.get("manager")

    if manager is not None:
        await manager.async_stop()

    unload_ok = True
    if PLATFORMS:
        unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)

    return unload_ok
