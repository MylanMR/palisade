"""Refuse to expose Palisade beyond this machine unless the operator explicitly opts in.

Palisade's web layer assumes local-only access: the page hands its session token to any
browser that loads it, and traffic is not encrypted. Binding to a network address without
compensating controls (an SSH tunnel, or a reverse proxy with TLS and authentication)
would let anyone on the network use the assistant and attempt the review login.

Rules enforced at startup:
  - Loopback address (127.0.0.0/8, ::1, localhost): start normally.
  - Any other address: refuse unless server.allow_remote is true in settings.yaml.
    Even then, start with a warning describing the exposure.
  - Session token disabled (server.require_token: false) on a non-loopback address:
    always refuse. There is no setting that allows this combination.
"""
from __future__ import annotations

import ipaddress
from typing import Any

REMOTE_WARNING = (
    "WARNING: Palisade is listening on {host}, which other machines can reach.\n"
    "  - Traffic is not encrypted.\n"
    "  - The page gives a session token to any browser that loads it, so anyone who can\n"
    "    reach this address can use the assistant and attempt the review login.\n"
    "  Put Palisade behind an SSH tunnel or a reverse proxy with TLS and authentication,\n"
    "  or set server.host back to 127.0.0.1."
)


def is_loopback(host: str) -> bool:
    h = (host or "").strip().strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False  # a hostname other than localhost could resolve anywhere


def check_exposure(settings: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Return (errors, warnings). Any error means Palisade must not start."""
    server = settings.get("server", {})
    host = str(server.get("host", "127.0.0.1"))
    allow_remote = server.get("allow_remote", False) is True
    require_token = server.get("require_token", True) is not False
    errors: list[str] = []
    warnings: list[str] = []

    if is_loopback(host):
        if not require_token:
            warnings.append("Session token is disabled (server.require_token: false). Any program "
                            "on this machine can use the assistant without it.")
        return errors, warnings

    if not require_token:
        errors.append(f"server.host is {host}, a network address, and server.require_token is false. "
                      "Palisade never runs on a network address without its session token. "
                      "Set require_token: true or host: 127.0.0.1.")
    if not allow_remote:
        errors.append(f"server.host is {host}, which other machines can reach. Palisade refuses to "
                      "start on a network address by default. Use an SSH tunnel to reach it remotely "
                      "(see README, Troubleshooting), or add 'allow_remote: true' under server: in "
                      "config/settings.yaml if you have put compensating controls in place.")
    if not errors:
        warnings.append(REMOTE_WARNING.format(host=host))
    return errors, warnings
