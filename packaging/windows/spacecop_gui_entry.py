"""PyInstaller entry point for the Windows GUI build (SpaceCopVPN.exe).

Kept separate from ``spacecop/gui/app.py`` so the frozen executable has a
stable, import-free entry and PyInstaller can collect the package.
"""

import multiprocessing
import sys


def main() -> int:
    multiprocessing.freeze_support()
    from spacecop.gui.app import main as gui_main

    return gui_main()


if __name__ == "__main__":
    sys.exit(main())
