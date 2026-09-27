"""Windows support must not break other platforms: modules import everywhere,
the whole-system factory picks the right backend, Wintun helpers degrade
gracefully off Windows."""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestWindowsSupport(unittest.TestCase):
    def test_modules_import_on_any_platform(self):
        import spacecop.tun.system as system
        import spacecop.tun.system_windows as system_windows
        import spacecop.tun.windows as windows
        self.assertTrue(hasattr(windows, "WindowsTun"))
        self.assertTrue(hasattr(system_windows, "WindowsSystemVPN"))
        self.assertTrue(callable(system.create_system_vpn))

    def test_wintun_helpers_off_windows(self):
        from spacecop.tun import windows
        if sys.platform.startswith("win"):
            self.skipTest("behaviour differs on Windows")
        self.assertFalse(windows.is_admin())
        with self.assertRaises(RuntimeError):
            windows.load_wintun()

    def test_factory_picks_backend(self):
        from spacecop.tun import system
        client = object()
        with mock.patch.object(sys, "platform", "linux"):
            vpn = system.create_system_vpn(client)
            self.assertEqual(type(vpn).__name__, "SystemVPN")
        with mock.patch.object(sys, "platform", "win32"):
            vpn = system.create_system_vpn(client)
            self.assertEqual(type(vpn).__name__, "WindowsSystemVPN")
        with mock.patch.object(sys, "platform", "darwin"):
            with self.assertRaises(RuntimeError):
                system.create_system_vpn(client)

    def test_guid_layout(self):
        import uuid
        from spacecop.tun.windows import _GUID
        u = uuid.UUID("7c5cff01-5c8d-4f0b-9b6e-5ac3c0b7a5e1")
        g = _GUID.from_uuid(u)
        self.assertEqual(g.Data1, 0x7C5CFF01)
        self.assertEqual(g.Data2, 0x5C8D)
        self.assertEqual(g.Data3, 0x4F0B)
        self.assertEqual(bytes(g.Data4), u.bytes[8:])

    def test_cli_vpn_refuses_without_privileges(self):
        from spacecop import cli
        with mock.patch("spacecop.tun.system.is_privileged", return_value=False):
            with self.assertRaises(SystemExit):
                cli.main(["vpn", "--uri", "spacecop://127.0.0.1:1/" + "00" * 32])


if __name__ == "__main__":
    unittest.main(verbosity=2)
