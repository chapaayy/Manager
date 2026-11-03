"""Compatibility entry point for the one-time v1 panel migration.

New tooling should use :mod:`v2.legacy.migrate_v1`.
"""
from .legacy.migrate_v1 import MigrationError, cli, inspect_legacy, migrate_panel

__all__ = ["MigrationError", "inspect_legacy", "migrate_panel", "cli"]

if __name__ == "__main__":
    cli()
