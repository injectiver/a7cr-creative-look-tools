"""Explicit A7CR identification / read-only service backup. No installation API.

identify only reads USB descriptors. backup authenticates the temporary USB
service identity, selects two allowlisted paths and reads programs/settings.
It never uploads a plugin, writes/deletes camera files or saves settings.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import sys
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "research/repos/a7c2-fl23-research/src/fl23/vendor"))
sys.path.insert(0, str(ROOT / "offline"))
from inspect_sources import save_json
from pmca.backup import BackupFile

MODEL = "ILCE-7CR"
VID, SERVICE = 0x054C, 0x0336
# These are the normal USB identities in the official A7CR 2.01 container.
# The exact product string and MSC interface must also match; PID alone is
# shared with other supported camera generations and is not model proof.
NORMAL_CANDIDATES = frozenset((0x0448, 0x047D, 0x0D15, 0x0D16, 0x0D19, 0x0D1A,
                              0x0DA4, 0x0DA5, 0x0E0A, 0x0E0E, 0x0E72, 0x0E76,
                              0x0E7E, 0x0E86, 0x0E8A, 0x0E8E))
PROGRAMS = {"/usr/lib/appFw.so": (99_960_744, "appFw.so"),
            "/cp/cpapp-b.bin": (18_085_024, "cpapp-b.bin")}
CP_UNITS = {0x02A40000: 4608, 0x02A40001: 8192,
            0x02A40002: 768, 0x02A4000D: 28672}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def private_owner(path, directory=False):
    os.chmod(path, 0o700 if directory else 0o600)
    if os.geteuid() == 0 and os.environ.get("SUDO_UID", "").isdigit() and os.environ.get("SUDO_GID", "").isdigit():
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
        if uid > 0:
            os.chown(path, uid, gid)


def usb_modules():
    import libusb_package
    import usb.core
    import usb.util
    import usb.backend.libusb1
    backend = usb.backend.libusb1.get_backend(find_library=libusb_package.find_library)
    if backend is None:
        raise ValueError("libusb runtime unavailable")
    return usb, backend


def descriptor_inventory():
    usb, backend = usb_modules()
    result = []
    for device in usb.core.find(find_all=True, idVendor=VID, backend=backend):
        item = {"usb": f"{VID:04x}:{device.idProduct:04x}"}
        try:
            item["product"] = usb.util.get_string(device, device.iProduct).strip() if device.iProduct else None
            item["interfaces"] = sorted({interface.bInterfaceClass for config in device for interface in config})
        except Exception as error:
            item["descriptor_error"] = type(error).__name__+": "+str(error)
        finally:
            usb.util.dispose_resources(device)
        result.append(item)
    return result


def normal_identity():
    usb, backend = usb_modules()
    identities = []
    for device in usb.core.find(find_all=True, idVendor=VID, backend=backend):
        try:
            if device.idProduct not in NORMAL_CANDIDATES:
                continue
            product = usb.util.get_string(device, device.iProduct).strip()
            if product.upper() != MODEL:
                continue
            interface = device.get_active_configuration()[(0, 0)]
            if interface.bInterfaceClass != 8:
                raise ValueError("A7CR is not in USB Mass Storage mode")
            serial = usb.util.get_string(device, device.iSerialNumber) if device.iSerialNumber else None
            if not serial or len(serial) < 8 or len(set(serial)) < 2 or serial != serial.strip():
                raise ValueError("A stable normal USB body serial is required")
            identities.append({"model": MODEL, "normal_usb": f"{VID:04x}:{device.idProduct:04x}",
                               "normal_pid": device.idProduct, "usb_serial_sha256": sha(serial.encode()),
                               "method": "USB_descriptors_and_MSC_interface"})
        finally:
            usb.util.dispose_resources(device)
    if len(identities) != 1:
        raise ValueError(f"Exactly one A7CR MSC camera is required; found {len(identities)}")
    return identities[0]


class Reader:
    """The only public camera operations are reads and temporary USB authentication."""
    def __init__(self, record=lambda *args, **kwargs: None, mac_capture=False):
        self.record = record
        self.healthy = True
        self.mac_capture = mac_capture
        self.location = None

    def call(self, label, function, *args):
        if not self.healthy:
            raise ValueError("Previous USB result is unknown; no more device commands")
        self.record("read_intent", operation=label)
        self.backend.reset()
        try:
            result = function(*args)
        except BaseException:
            self.healthy = False
            raise
        self.record("read_returned", operation=label)
        return result

    def wait_for_service(self, usb, backend, seconds=25):
        """Observe re-enumeration only; never repeat authentication or send packets."""
        deadline = time.monotonic()+seconds
        previous = None
        try:
            while True:
                devices = list(usb.core.find(find_all=True, idVendor=VID, backend=backend))
                observed = sorted((device.idProduct, device.bus, tuple(device.port_numbers or ())) for device in devices)
                if observed != previous:
                    self.record("usb_transition_observed", devices=[
                        {"pid": f"{pid:04x}", "bus": bus, "ports": list(ports),
                         "on_expected_port": self.location == (bus, ports) if self.location else None}
                        for pid, bus, ports in observed])
                    previous = observed
                services = [device for device in devices if device.idProduct == SERVICE]
                chosen = services[0] if len(services) == 1 else None
                for device in devices:
                    if device is not chosen:
                        usb.util.dispose_resources(device)
                if len(services) > 1:
                    raise ValueError("Ambiguous service devices; no authentication retry")
                if chosen is not None:
                    if self.location and (chosen.bus, tuple(chosen.port_numbers or ())) != self.location:
                        usb.util.dispose_resources(chosen)
                        raise ValueError("Service USB physical port differs; no authentication retry")
                    self.record("service_usb_identity_observed", pid=f"{SERVICE:04x}")
                    return chosen
                if time.monotonic() >= deadline:
                    self.record("service_transition_timeout", wait_seconds=seconds,
                                authentication_repeated=False, last_observed_pids=[f"{pid:04x}" for pid, _, _ in observed])
                    raise TimeoutError("Service identity did not appear; no authentication retry")
                time.sleep(0.5)
        except BaseException:
            self.healthy = False
            raise

    def __enter__(self):
        from pmca.usb.driver.generic import GenericUsbDriver
        from pmca.usb.driver.generic.libusb import UsbBackend
        from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera
        usb, backend = usb_modules()
        self.usb = usb
        self.identity = normal_identity()
        expected=getattr(self,'expected_usb_serial_sha256',None)
        if expected is not None and self.identity['usb_serial_sha256']!=expected:
            raise ValueError('Normal USB body differs from the prepared job; no authentication performed')
        if list(usb.core.find(find_all=True, idVendor=VID, idProduct=SERVICE, backend=backend)):
            raise ValueError("A pre-existing Sony service device needs inspection before new authentication")

        class Bounded(UsbBackend):
            def __del__(inner):
                # The Reader explicitly owns handles across re-enumeration.
                pass
            def reset(inner):
                inner.deadline = time.monotonic()+getattr(inner, "operation_budget_seconds", 180)
            def timeout(inner, requested=None):
                left = int((inner.deadline-time.monotonic())*1000)
                if left <= 0:
                    raise TimeoutError("Read operation exceeded its time budget")
                return min(left, requested or 180000)
            def read(inner, endpoint, length, timeout=None):
                return super().read(endpoint, length, inner.timeout(timeout))
            def write(inner, endpoint, raw):
                inner.dev.default_timeout = inner.timeout()
                return super().write(endpoint, raw)

        normal = usb.core.find(idVendor=VID, idProduct=self.identity["normal_pid"], backend=backend)
        serial = usb.util.get_string(normal, normal.iSerialNumber) if normal and normal.iSerialNumber else None
        if not serial or sha(serial.encode()) != self.identity["usb_serial_sha256"]:
            if normal is not None:
                usb.util.dispose_resources(normal)
            raise ValueError("Normal USB body binding changed before authentication")
        if self.mac_capture:
            import mac_usb
            self.location, self.normal_detached = mac_usb.capture(usb, normal, self.identity, self.record)
            print('开始切换服务模式：等待期间请先不要操作相机上的 USB／MSC 选择；Mac 若询问允许配件连接，可点允许。',flush=True)
            print('只有终端明确显示“读取已结束”后，再按提示选择 MSC。',flush=True)
        self.record("normal_authentication_intent", identity=self.identity)
        try:
            transport = Bounded(normal)
            transport.reset()
            auth = SonySenserAuthDevice(GenericUsbDriver(transport))
            auth.start()
            auth.authenticate()
        except BaseException:
            self.healthy = False
            raise
        finally:
            usb.util.dispose_resources(normal)
        self.record("normal_authentication_returned")
        self.device = self.wait_for_service(usb, backend)
        self.backend = Bounded(self.device)
        self.backend.reset()
        if self.mac_capture:
            if self.device.is_kernel_driver_active(0):
                usb.util.dispose_resources(self.device)
                raise ValueError("Unexpected kernel driver on the service interface")
            usb.util.claim_interface(self.device, 0)
        self.auth = SonySenserAuthDevice(GenericUsbDriver(self.backend))
        self.record("service_authentication_intent")
        try:
            self.auth.start()
            self.auth.authenticate()
            self.channel = SonySenserDevice(self.auth.driver)
            self.camera = SonySenserCamera(self.channel)
        except BaseException:
            self.healthy = False
            usb.util.dispose_resources(self.device)
            raise
        self.record("service_authentication_returned")
        return self

    def read_program(self, path):
        if path not in PROGRAMS:
            raise ValueError("Camera path is not allowlisted")
        selected = "/tmp/jiritsu/../../"+path.lstrip("/")
        self.jiritsu(15, b"\0"+selected.encode("ascii")+b"\0")
        raw = self.jiritsu(17, b"\0\xff\0")
        if len(raw) != PROGRAMS[path][0]:
            raise ValueError("Program length differs; preserve the read outcome")
        return raw

    def jiritsu(self, command, payload):
        if command not in (15, 17):
            raise ValueError("Only path selection and file read are allowed")
        status, raw = self.call(f"JIRITSU_{command}", self.channel.sendSenserPacket,
                                0x40, struct.pack("<HH", 0x1001, command)+payload)
        if status or len(raw) < 4 or struct.unpack_from("<I", raw)[0]:
            self.healthy = False
            raise ValueError("Jiritsu read failed; no automatic retry")
        return raw[4:]

    def snapshot(self, memory):
        if type(memory) is not bool:
            raise ValueError("Snapshot source must be an explicit boolean")
        return self.call("BACKUP_READ_MEMORY" if memory else "BACKUP_READ_FLASH",
                         self.camera.getBackupPresetData, memory)

    def __exit__(self, *args):
        exit_sent = False
        try:
            if self.healthy:
                self.record("service_exit_intent")
                self.auth.stop()
                self.record("service_exit_returned")
                exit_sent = True
        finally:
            self.usb.util.dispose_resources(self.device)
        if exit_sent:
            print("读取已结束，等待普通 USB 连接；相机若询问模式，请选影像传输（MSC）。", flush=True)
            usb, backend = usb_modules()
            deadline = time.monotonic()+60
            while True:
                normal = usb.core.find(idVendor=VID, idProduct=self.identity["normal_pid"], backend=backend)
                if normal is not None:
                    location = normal.bus, tuple(normal.port_numbers or ())
                    try:
                        serial = usb.util.get_string(normal, normal.iSerialNumber) if normal.iSerialNumber else None
                        if self.location and location != self.location:
                            raise ValueError("Normal USB returned on a different physical port")
                        if not serial or sha(serial.encode()) != self.identity["usb_serial_sha256"]:
                            raise ValueError("Normal USB body binding differs after service exit")
                    finally:
                        usb.util.dispose_resources(normal)
                    self.record("normal_usb_returned")
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("Reads ended, but normal USB return was not confirmed; preserve this job")
                time.sleep(0.5)


def backup_sections(raw):
    sections = []
    for match in re.finditer(b"BK4\0", raw):
        try:
            parsed = BackupFile(io.BytesIO(raw[match.start()-12:]))
            sections.append(dict(parsed.listProperties()))
        except Exception:
            continue
    if len(sections) != 2:
        raise ValueError("Expected two complete checksum-valid BK4 sections")
    if 0x00E70003 not in sections[0] or 0x02A40001 not in sections[1]:
        raise ValueError("AP/CP backup section identity differs")
    return sections


def run_backup(workspace, second, version, mac_capture=False):
    if version != "2.01":
        raise ValueError("The camera version screen must say 2.01")
    workspace, second = workspace.resolve(), second.resolve()
    if workspace == second or workspace in second.parents or second in workspace.parents:
        raise ValueError("Two separate fresh backup directories are required")
    workspace.mkdir(parents=True, exist_ok=False)
    second.mkdir(parents=True, exist_ok=False)
    private_owner(workspace, True)
    private_owner(second, True)
    events = []
    def record(phase, **detail):
        events.append({"phase": phase, "utc": datetime.now(timezone.utc).isoformat(), **detail})
        save_json(workspace / "events.private.json", events)
        private_owner(workspace / "events.private.json")
    files = {}
    def store(name, raw):
        for folder in (workspace, second):
            target = folder / name
            with target.open("xb") as output:
                output.write(raw); output.flush(); os.fsync(output.fileno())
            private_owner(target)
            if target.read_bytes() != raw:
                raise ValueError("Independent local backup verification failed")
        files[name] = {"bytes": len(raw), "sha256": sha(raw)}
    try:
        with Reader(record, mac_capture=mac_capture) as camera:
            record("body_identified", identity=camera.identity)
            for path, (_, filename) in PROGRAMS.items():
                raw = camera.read_program(path)
                store(filename, raw)
            snapshots = {}
            for memory in (True, False):
                raw = camera.snapshot(memory)
                store("settings-memory.private.bin" if memory else "settings-flash.private.bin", raw)
                snapshots[memory] = backup_sections(raw)
            serials = [snapshot[0][0x00E70003].data for snapshot in snapshots.values()]
            if len(serials[0]) != 4 or serials[0] != serials[1]:
                raise ValueError("AP memory/flash body identity differs")
            for key in CP_UNITS:
                # Both complete checksum-verified snapshots already contain
                # CP units. A redundant direct READ40 of unit00 timed out on
                # the A7CR; no such protocol request belongs in this workflow.
                raw = snapshots[True][1][key].data
                if len(raw) != CP_UNITS[key] or raw != snapshots[False][1][key].data:
                    raise ValueError("CP unit size or saved/live snapshot differs")
                store(f"unit-{key:08x}.private.bin", raw)
            identity = dict(camera.identity, ap_serial_sha256=sha(serials[0].hex().encode("ascii")))
        manifest = {"schema": "a7cr-read-only-backup/1", "phase": "READ_ONLY_BACKUP_COMPLETE",
                    "firmware_version_user_confirmed": version, "identity": identity,
                    "files": files, "native_worker_uploaded": False,
                    "camera_files_or_settings_written": False,
                    "second_copy_same_volume": workspace.stat().st_dev == second.stat().st_dev}
        for folder in (workspace, second):
            save_json(folder / "backup.private.json", manifest)
            private_owner(folder / "backup.private.json")
        record("complete")
        print(json.dumps({"phase": manifest["phase"], "files": len(files),
                          "workspace": str(workspace), "second_copy": str(second),
                          "same_volume": manifest["second_copy_same_volume"]}, indent=2))
    except BaseException as error:
        record("stopped_no_retry", error_type=type(error).__name__, error=str(error))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    identify = sub.add_parser("identify", help="Only read normal USB descriptors; no service authentication")
    identify.add_argument("--inventory", action="store_true", help="List Sony product/interface descriptors without serial numbers")
    identify.add_argument("--mac-status", action="store_true", help="Read and cross-check the camera's macOS storage children")
    backup = sub.add_parser("backup", help="Read programs and body settings, with two verified local copies")
    backup.add_argument("--workspace", required=True, type=Path)
    backup.add_argument("--backup-copy", required=True, type=Path)
    backup.add_argument("--firmware-version", required=True)
    backup.add_argument("--mac-capture", action="store_true", help="With administrator permission, unmount verified camera volumes and temporarily capture only its USB interface")
    args = parser.parse_args()
    lock_path = ROOT / "private/device.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == "identify":
            if args.mac_status:
                import mac_usb
                identity = normal_identity()
                registry, media = mac_usb.camera_media(identity)
                print(json.dumps({"identity": identity, "registry": registry, "camera_media": media}, indent=2))
            else:
                print(json.dumps(descriptor_inventory() if args.inventory else normal_identity(), indent=2))
        else:
            if args.mac_capture and os.geteuid() != 0:
                raise PermissionError("--mac-capture requires administrator authorization; use sudo in your terminal")
            os.umask(0o077)
            run_backup(args.workspace, args.backup_copy, args.firmware_version, args.mac_capture)


if __name__ == "__main__":
    main()
