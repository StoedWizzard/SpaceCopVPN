"""PyInstaller entry point for the Windows CLI build (spacecop.exe)."""

import multiprocessing
import sys


def main() -> int:
    multiprocessing.freeze_support()
    from spacecop.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    sys.exit(main())
