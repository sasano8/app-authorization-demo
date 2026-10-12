"""Dry run of startup settings: python -m app.check

Prints one line per setting (never the value itself) and exits 1 on any failure.
"""
import sys

from app.main import check_env


def main():
    checks = check_env()
    for c in checks:
        print(f"{c.name}: {'true' if c.ok else 'false'}" + (f"  # {c.error}" if not c.ok else ""))
    return 0 if all(c.ok for c in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
