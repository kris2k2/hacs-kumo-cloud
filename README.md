# Kumo Cloud Home Assistant Integration

This repository contains a Home Assistant custom integration for controlling Mitsubishi Kumo Cloud thermostats. The integration is designed to be installed through [HACS](https://hacs.xyz/).

## Features

- Home Assistant configuration flow that prompts for the Kumo Cloud username and password (credentials will be used for SSO in a future update).
- Boilerplate structure ready for upcoming functionality including device discovery and state updates.

## Installation

1. Add this repository to HACS as a custom repository (`Integration` category).
2. Install the **Kumo Cloud** integration from the HACS store.
3. Restart Home Assistant.
4. In Home Assistant, go to **Settings → Devices & Services → Add Integration** and search for **Kumo Cloud**.
5. Enter your Kumo Cloud username and password when prompted.

## Development

The integration follows the standard Home Assistant custom integration boilerplate. Future development will add:

1. Single sign-on token exchange.
2. Thermostat discovery, capabilities, and API actions.
3. Websocket-based state polling and updates to Home Assistant.

Contributions are welcome!
