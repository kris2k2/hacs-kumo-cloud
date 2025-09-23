"""Constants for the Kumo Cloud integration."""

from __future__ import annotations

from datetime import timedelta

from homeassistant.const import Platform

DOMAIN = "kumo_cloud"

APP_VERSION = "3.2.0"

API_BASE_URL = "https://app-prod.kumocloud.com"
LOGIN_ENDPOINT = "/v3/login"

SOCKET_IO_BASE_URL = "https://socket-prod.kumocloud.com/socket.io/"
SOCKET_IO_WEBSOCKET_URL = "wss://socket-prod.kumocloud.com/socket.io/"

PREFERRED_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "hass-kumo-cloud/1.0",
    "x-app-version": APP_VERSION,
    "app-env": "prd",
    "x-allow-cache": "true",
}

TOKEN_REFRESH_LEEWAY = timedelta(seconds=90)
WEBSOCKET_RETRY_DELAY = timedelta(seconds=15)

PLATFORMS: list[Platform] = [Platform.SENSOR]
