"""Test-only stand-in for the macOS Keychain (never packaged: package_app.sh copies server.py/evidence.py only,
and CI fails if a shipped file mentions this module).

Shipped evidence.py has exactly one key store, the Keychain via AgentReinsKeychainHelper. Unit tests that need a
signing key swap evidence's Keychain functions for this dict with mock.patch, so no environment switch or
in-memory backend exists in the code that ships.
"""
from __future__ import annotations

from unittest import mock


class FakeKeychain:
    backend = "test-fake-keychain"

    def __init__(self) -> None:
        self.items: dict[str, bytes] = {}

    def lookup(self, account: str) -> tuple[str, bytes | None]:
        data = self.items.get(account)
        return ("found", data) if data is not None else ("missing", None)

    def set(self, account: str, value: bytes) -> bool:
        self.items[account] = bytes(value)
        return True

    def delete(self, account: str) -> bool:
        self.items.pop(account, None)
        return True

    def patches(self, evidence) -> list:
        """mock.patch objects that route evidence.py's Keychain calls to this fake (start/stop them yourself)."""
        return [
            mock.patch.object(evidence, "_keychain_backend", lambda: self.backend),
            mock.patch.object(evidence, "_keychain_lookup", self.lookup),
            mock.patch.object(evidence, "keychain_set", self.set),
            mock.patch.object(evidence, "keychain_delete", self.delete),
        ]


# One shared fake per test process (the old in-memory store was module-global too).
FAKE = FakeKeychain()
