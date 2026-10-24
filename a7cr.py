#!/usr/bin/env python3
"""A7CR host tools. Camera access requires an explicit identify/backup command.

Project operations wrap reviewed per-body research packages. Only explicitly
selected checkpoint/install/verify/restore operations can open a camera.
"""
from __future__ import annotations
import argparse
import importlib.metadata
import json
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VERSION = "0.2.0-research"


def doctor():
    from tools.upstream import status
    versions = {}
    for name in ("pyusb", "libusb-package", "numpy", "scipy", "rawpy", "Pillow"):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    print(json.dumps({"version": VERSION, "python": platform.python_version(),
        "system": platform.system(), "machine": platform.machine(),
        "host_tested_family": platform.system() == "Darwin" and platform.machine() == "arm64",
        "packages": versions, "upstream": status(), "camera_opened": False,
        "serial_numbers_or_hostnames_collected": False,
        "device_installation_cli": True, "requires_reviewed_body_bound_package": True,
        "generic_camera_installer": False}, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="Report a non-identifying host/dependency inventory; no USB access")
    boot = sub.add_parser("bootstrap", help="Fetch pinned upstream sources; no firmware/DCP download")
    boot.add_argument("--research", action="store_true", help="Also fetch firmware-analysis and assembler sources")
    sub.add_parser("identify", help="Read Sony USB product/interface descriptors; no authentication or serial output")
    backup = sub.add_parser("backup", help="Explicit service-mode read-only backup; macOS administrator access required")
    backup.add_argument("--workspace", required=True, type=Path)
    backup.add_argument("--backup-copy", required=True, type=Path)
    backup.add_argument("--firmware-version", required=True, choices=("2.01",))
    fit = sub.add_parser("fit-dcp", help="Fit a local DCP into a non-installable 1215-byte ST-relative candidate; offline")
    fit.add_argument("profile", type=Path)
    fit.add_argument("--name", required=True)
    fit.add_argument("--slot", type=int, choices=range(1,7), required=True)
    model = fit.add_mutually_exclusive_group(required=True)
    model.add_argument("--calibration", type=Path)
    model.add_argument("--use-upstream-model", action="store_true", help="Explicitly accept the provisional one-scene A7C II model")
    fit.add_argument("--output", type=Path, required=True)
    photo = sub.add_parser("analyze-photos", help="Read local RAW+JPEG pairs; save metadata/stats/previews to a new local directory")
    photo.add_argument("--input", type=Path, required=True)
    photo.add_argument("--stems", nargs="+", required=True)
    photo.add_argument("--output", type=Path, required=True)
    photo.add_argument("--exiftool", type=Path)
    project=sub.add_parser('project',help='Agent-neutral private workspaces; JSON stdout, explicit camera operations')
    project_sub=project.add_subparsers(dest='project_command',required=True)
    init=project_sub.add_parser('init',help='Create a fresh private workspace; no camera access')
    init.add_argument('--project',type=Path,required=True)
    init.add_argument('--firmware-version',choices=('2.01',),required=True)
    state=project_sub.add_parser('status',help='Report recorded local phases; no camera access')
    state.add_argument('--project',type=Path,required=True)
    profiles=project_sub.add_parser('fit-profiles',help='Fit three explicitly supplied local preset DCPs; offline only')
    profiles.add_argument('--project',type=Path,required=True)
    profiles.add_argument('--classic-chrome',type=Path,required=True)
    profiles.add_argument('--pro-neg-std',type=Path,required=True)
    profiles.add_argument('--astia',type=Path,required=True)
    profiles.add_argument('--use-upstream-model',action='store_true',required=True)
    run=project_sub.add_parser('run',help='Run one explicitly selected operation, never retry or auto-advance')
    run.add_argument('--project',type=Path,required=True)
    run.add_argument('--stage',choices=('single','portrait'),required=True)
    run.add_argument('--operation',choices=('build-assets','checkpoint','prepare','native-check','finalize','validate','install','verify','restore','inspect-exit','review-exit'),required=True)
    run.add_argument('--battery-percent',type=int)
    run.add_argument('--checkpoint',type=Path)
    args = parser.parse_args(argv)
    if args.command=='project':
        from tools import workflow
        try:
            if args.project_command=='init':result=workflow.initialize(args.project,args.firmware_version)
            elif args.project_command=='status':result=workflow.status(args.project)
            elif args.project_command=='fit-profiles':result=workflow.fit_profiles(args.project,
                {1:args.classic_chrome,2:args.pro_neg_std,3:args.astia},use_upstream_model=args.use_upstream_model)
            else:result=workflow.run(args.project,args.stage,args.operation,battery=args.battery_percent,checkpoint=args.checkpoint)
            print(json.dumps(result,ensure_ascii=False,indent=2))
            return 0 if result.get('ok') else 2
        except (OSError,RuntimeError,ValueError,KeyError,subprocess.CalledProcessError) as exc:
            print(json.dumps({'ok':False,'error':type(exc).__name__,'message':str(exc),'automatic_retry':False},ensure_ascii=False))
            return 2
    elif args.command == "doctor":
        doctor()
    elif args.command == "bootstrap":
        from tools.upstream import bootstrap
        bootstrap(args.research)
    elif args.command in ("identify", "backup"):
        if platform.system() != "Darwin":
            parser.error("This project's public camera commands are macOS-only")
        from tools.upstream import require
        require("a7c2")
        cmd = [sys.executable, str(ROOT / "device/read_backup.py")]
        if args.command == "identify":
            cmd += ["identify", "--inventory"]
        else:
            cmd += ["backup", "--workspace", str(args.workspace), "--backup-copy", str(args.backup_copy),
                    "--firmware-version", args.firmware_version, "--mac-capture"]
        from tools.workflow import host_usb_lock
        with host_usb_lock():return subprocess.call(cmd)
    elif args.command == "fit-dcp":
        from tools.fit import run
        run(args)
    elif args.command == "analyze-photos":
        from tools.photos import run
        run(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print("Stopped; no automatic retry: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
