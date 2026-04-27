"""Unit tests for IDS mode normalization and startup precedence."""

import unittest

from core.ids_mode import (
    explicit_ids_mode_from_env,
    resolve_startup_ids_mode,
)


class _StateStoreStub(object):
    def __init__(self, mode):
        self.mode = mode

    def current_mode(self, default="threshold"):
        return self.mode or default


class IDSModeStartupTests(unittest.TestCase):
    def test_explicit_ids_mode_prefers_primary_env_variable(self):
        mode = explicit_ids_mode_from_env(
            {
                "SDN_IDS_MODE": "hybrid",
                "SDN_ML_MODE": "ml",
            }
        )

        self.assertEqual(mode, "hybrid")

    def test_explicit_ids_mode_uses_legacy_env_variable_when_needed(self):
        mode = explicit_ids_mode_from_env(
            {
                "SDN_ML_MODE": "hybrid",
            }
        )

        self.assertEqual(mode, "hybrid")

    def test_resolve_startup_ids_mode_prefers_explicit_env_over_persisted_state(self):
        mode = resolve_startup_ids_mode(
            "threshold",
            state_store=_StateStoreStub("ml"),
            env={"SDN_IDS_MODE": "hybrid"},
        )

        self.assertEqual(mode, "hybrid")

    def test_resolve_startup_ids_mode_falls_back_to_persisted_state(self):
        mode = resolve_startup_ids_mode(
            "threshold",
            state_store=_StateStoreStub("ml"),
            env={},
        )

        self.assertEqual(mode, "ml")


if __name__ == "__main__":
    unittest.main()
