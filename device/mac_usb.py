"""Narrow macOS ownership handling for an already identified A7CR.

Registry/unmount design derived from MDHan/a7c2-fl23-macos host.py/session.py
at dd697995c85ddf32ca9ce19b870d048769fadc91. See licenses/MDHan-MIT.txt.
This module has no camera protocol or firmware operations.
"""
from __future__ import annotations

import os
import plistlib
import re
import subprocess
import time


def command(*args):
    return subprocess.check_output(args, timeout=30)


def walk(item):
    if isinstance(item, list):
        for child in item:
            yield from walk(child)
    elif isinstance(item, dict):
        yield item
        yield from walk(item.get("IORegistryEntryChildren", []))


def sony_usb_snapshot():
    """Observe registry descriptors only; omit serials and never open USB."""
    tree = plistlib.loads(command("/usr/sbin/ioreg", "-p", "IOUSB", "-l", "-a"))
    return sorted(
        ({"pid": f"{node['idProduct']:04x}",
          "location_id": node.get("locationID"),
          "product": node.get("USB Product Name")}
         for node in walk(tree)
         if node.get("IOObjectClass") == "IOUSBHostDevice"
         and node.get("idVendor") == 0x054C
         and isinstance(node.get("idProduct"), int)),
        key=lambda item: (item["pid"], str(item["location_id"])),
    )


def validate_media(tree, identity, info_for):
    targets = [node for node in walk(tree)
               if node.get("IOObjectClass") == "IOUSBHostDevice"
               and node.get("idVendor") == 0x054C
               and node.get("idProduct") == identity["normal_pid"]
               and node.get("USB Product Name") == "ILCE-7CR"]
    if len(targets) != 1:
        raise ValueError("Exactly one registry-confirmed A7CR is required")
    registry = targets[0].get("IORegistryEntryID")
    if registry is None:
        raise ValueError("USB registry identity is unavailable")
    media = {}
    for item in walk(targets[0]):
        if item.get("IOObjectClass") != "IOMedia" or not item.get("BSD Name"):
            continue
        name = item["BSD Name"]
        if not re.fullmatch(r"disk[0-9]+(?:s[0-9]+)*", name):
            raise ValueError("Unexpected camera disk identifier")
        info = info_for(name)
        if (info.get("DeviceIdentifier") != name or info.get("Internal") is not False
                or info.get("OSInternalMedia") is not False or info.get("BusProtocol") != "USB"):
            raise ValueError("Disk is not the expected external USB media")
        media[name] = {"parent": info.get("ParentWholeDisk"), "whole": info.get("WholeDisk"),
                       "mounted": bool(info.get("MountPoint"))}
    for name, row in media.items():
        if row["whole"] is True:
            if not re.fullmatch(r"disk[0-9]+", name):
                raise ValueError("Unexpected whole-disk identifier")
        elif row["parent"] not in media or media[row["parent"]]["whole"] is not True:
            raise ValueError("Partition parent is not a verified camera disk")
    return registry, media


def camera_media(identity):
    tree = plistlib.loads(command("/usr/sbin/ioreg", "-p", "IOService", "-l", "-a"))
    return validate_media(tree, identity,
                          lambda name: plistlib.loads(command("/usr/sbin/diskutil", "info", "-plist", name)))


def unmount_verified(identity, record):
    previous, stable_since = None, None
    deadline = time.monotonic()+20
    while True:
        registry, media = camera_media(identity)
        topology = (registry, tuple(sorted((name, row["parent"], row["whole"]) for name, row in media.items())))
        now = time.monotonic()
        if any(row["whole"] for row in media.values()):
            if topology != previous:
                previous, stable_since = topology, now
            elif now-stable_since >= 3:
                break
        if now >= deadline:
            raise ValueError("Camera disk topology did not stabilize; capture refused")
        time.sleep(0.5)
    for name in sorted(name for name, row in media.items() if row["whole"]):
        current_id, current = camera_media(identity)
        if current_id != registry or set(current) != set(media):
            raise ValueError("Camera/disk identity changed before unmount")
        record("host_camera_unmount_intent", disk=name, registry=registry)
        print("正常卸载已核实的相机磁盘："+name, flush=True)
        command("/usr/sbin/diskutil", "unmountDisk", "/dev/"+name)
        record("host_camera_unmount_returned", disk=name)
    current_id, current = camera_media(identity)
    if current_id != registry or set(current) != set(media) or any(row["mounted"] for row in current.values()):
        raise ValueError("Not all verified camera volumes unmounted; capture refused")


def capture(usb, device, identity, record):
    if os.geteuid() != 0:
        raise PermissionError("macOS USB capture requires administrator authorization; use the prepared sudo command")
    interface = device.get_active_configuration()[(0, 0)]
    if (interface.bInterfaceClass, interface.bInterfaceSubClass, interface.bInterfaceProtocol) != (8, 6, 0x50):
        raise ValueError("Unexpected A7CR MSC interface")
    location = device.bus, tuple(device.port_numbers or ())
    if not location[1]:
        raise ValueError("Physical USB port identity is unavailable")
    unmount_verified(identity, record)
    detached = False
    try:
        if device.is_kernel_driver_active(0):
            record("host_kernel_driver_detach_intent")
            device.detach_kernel_driver(0)
            detached = True
            record("host_kernel_driver_detach_returned")
        usb.util.claim_interface(device, 0)
        record("host_usb_interface_claimed")
        return location, detached
    except BaseException:
        if detached:
            device.attach_kernel_driver(0)
        usb.util.dispose_resources(device)
        raise
