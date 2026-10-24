"""Offline tests of disk ownership guards; all OS and USB calls are mocked."""
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import mac_usb


class MacOwnershipTests(unittest.TestCase):
    def test_registry_observer_omits_serials_and_uses_only_ioreg(self):
        sony = {'IOObjectClass': 'IOUSBHostDevice', 'idVendor': 0x054C,
                'idProduct': 0x0336, 'locationID': 2097152,
                'USB Product Name': 'Sony USB Device', 'USB Serial Number': 'PRIVATE'}
        other = dict(sony, idVendor=0x05AC)
        with patch.object(mac_usb, 'command', return_value=mac_usb.plistlib.dumps([sony, other])) as command:
            result = mac_usb.sony_usb_snapshot()
        self.assertEqual(result, [{'pid': '0336', 'location_id': 2097152, 'product': 'Sony USB Device'}])
        self.assertNotIn('PRIVATE', str(result))
        command.assert_called_once_with('/usr/sbin/ioreg', '-p', 'IOUSB', '-l', '-a')

    def fixture(self):
        identity = {"normal_pid": 0x0E86}
        target = {"IOObjectClass": "IOUSBHostDevice", "idVendor": 0x054C,
                  "idProduct": 0x0E86, "USB Product Name": "ILCE-7CR", "IORegistryEntryID": 101,
                  "IORegistryEntryChildren": [{"IOObjectClass": "IOMedia", "BSD Name": name}
                                               for name in ("disk4", "disk4s1")]}
        info = {name: {"DeviceIdentifier": name, "Internal": False, "OSInternalMedia": False,
                        "BusProtocol": "USB", "WholeDisk": name == "disk4", "ParentWholeDisk": "disk4",
                        "MountPoint": "/Volumes/Synthetic" if name.endswith("s1") else None}
                for name in ("disk4", "disk4s1")}
        return identity, target, info

    def test_only_camera_descendants_are_included(self):
        identity, target, info = self.fixture()
        other = {"IOObjectClass": "IOMedia", "BSD Name": "disk9"}
        registry, media = mac_usb.validate_media([target, other], identity, info.__getitem__)
        self.assertEqual(registry, 101)
        self.assertEqual(set(media), {"disk4", "disk4s1"})

    def test_wrong_camera_model_is_rejected(self):
        identity, target, info = self.fixture()
        target["USB Product Name"] = "ILCE-7CM2"
        with self.assertRaises(ValueError):
            mac_usb.validate_media(target, identity, info.__getitem__)

    def test_internal_or_non_usb_disk_is_rejected(self):
        for key, value in (("Internal", True), ("OSInternalMedia", True), ("BusProtocol", "PCI-Express")):
            identity, target, info = self.fixture()
            info["disk4"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                mac_usb.validate_media(target, identity, info.__getitem__)

    def test_partition_cannot_point_at_another_disk(self):
        identity, target, info = self.fixture()
        info["disk4s1"]["ParentWholeDisk"] = "disk9"
        with self.assertRaises(ValueError):
            mac_usb.validate_media(target, identity, info.__getitem__)

    def test_unmount_is_non_forced_and_camera_scoped(self):
        identity, target, info = self.fixture()
        registry, mounted = mac_usb.validate_media(target, identity, info.__getitem__)
        unmounted = deepcopy(mounted)
        for row in unmounted.values():
            row["mounted"] = False
        states = [(registry, mounted), (registry, mounted), (registry, mounted), (registry, unmounted)]
        with (patch.object(mac_usb, "camera_media", side_effect=states),
              patch.object(mac_usb, "command") as command,
              patch.object(mac_usb.time, "monotonic", side_effect=[0, 0, 4]),
              patch.object(mac_usb.time, "sleep")):
            mac_usb.unmount_verified(identity, Mock())
        command.assert_called_once_with("/usr/sbin/diskutil", "unmountDisk", "/dev/disk4")

    def test_disk_identity_change_stops_before_unmount(self):
        identity, target, info = self.fixture()
        registry, media = mac_usb.validate_media(target, identity, info.__getitem__)
        with (patch.object(mac_usb, "camera_media", side_effect=[(registry, media), (registry, media), (999, media)]),
              patch.object(mac_usb, "command") as command,
              patch.object(mac_usb.time, "monotonic", side_effect=[0, 0, 4]),
              patch.object(mac_usb.time, "sleep")):
            with self.assertRaises(ValueError):
                mac_usb.unmount_verified(identity, Mock())
        command.assert_not_called()

    def test_unmount_failure_never_detaches_driver(self):
        device = SimpleNamespace(bus=1, port_numbers=(2,),
                                 get_active_configuration=Mock(return_value={(0, 0): SimpleNamespace(
                                     bInterfaceClass=8, bInterfaceSubClass=6, bInterfaceProtocol=0x50)}),
                                 is_kernel_driver_active=Mock(), detach_kernel_driver=Mock())
        with (patch.object(mac_usb.os, "geteuid", return_value=0),
              patch.object(mac_usb, "unmount_verified", side_effect=RuntimeError("busy"))):
            with self.assertRaises(RuntimeError):
                mac_usb.capture(Mock(), device, {"normal_pid": 0x0E86}, Mock())
        device.is_kernel_driver_active.assert_not_called()
        device.detach_kernel_driver.assert_not_called()

    def test_missing_admin_permission_stops_before_host_actions(self):
        with (patch.object(mac_usb.os, "geteuid", return_value=501),
              patch.object(mac_usb, "unmount_verified") as unmount):
            with self.assertRaises(PermissionError):
                mac_usb.capture(Mock(), Mock(), {"normal_pid": 0x0E86}, Mock())
        unmount.assert_not_called()


if __name__ == "__main__":
    unittest.main()
