"""Capture a fresh FL23 checkpoint and six-look settings plan. Read-only USB.

No firmware, resource, saved-setting or retained-image writes. The temporary
loaded-AP diagnostic is the previously simulated read-only implementation.
"""
from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

from diagnose_fl23 import DiagnosticSession, invoke as runtime_invoke, parameter_report
from fl23_install import Package, Job, PATHS, durable_json, preserved
from read_backup import ROOT, private_owner, backup_sections, CP_UNITS
from preflight_fl23 import sha

sys.path.insert(0, str(ROOT/"research/repos/a7c2-fl23-research/src/looks"))
from looktool import backupstore, resources, devicesettings

RESOURCE_NAMES = tuple(json.loads((ROOT/"research/repos/a7c2-fl23-research/src/looks/assets/resource-files.json").read_text()))
WORKSPACE = ROOT/"private/install/fl23"
NAMES = ("Classic Neg.", "Classic Chrome", "Nostalgic Neg.", "Eterna", "GR Positive Film", "GR Negative Film")


class CheckpointSession(DiagnosticSession):
    def read_resource(self, filename):
        if filename not in RESOURCE_NAMES:
            raise ValueError("Resource path is not allowlisted")
        self.jiritsu(15,b"\0/tmp/jiritsu/../../usr/share/app/"+filename.encode("ascii")+b"\0")
        raw=self.jiritsu(17,b"\0\xff\0")
        if not 5740 <= len(raw) <= 524288:
            raise ValueError("Resource read length differs")
        parsed=resources.decode(raw)
        if parsed["group"]!=5 or parsed["count"]!=2860:
            raise ValueError("This first A7CR import requires the native 2860-title layout")
        return raw


def settings_plan(ap,ram,saved):
    expected="4ff7051bfca944b02ce150f911357d5d0173bbf2bfad01a08c9dea13a0dac019"
    if sha(ap)!=expected:
        raise ValueError("Settings adapter requires the exact reviewed A7CR FL23 AP")
    def descriptor(attribute):
        row=struct.unpack_from("<8I",ap,0x57c6710+(attribute-0x14ea)*32)
        if row[6]!=attribute or row[1]>>16!=0x02cf:
            raise ValueError("A7CR ordinary-slot descriptor identity differs")
        return row
    fields=[]
    for slot in range(1,7):
        selector=slot+9;row=descriptor(0x14ea+selector);key=row[1]
        if row[0]!=3 or row[2]!=0x10000 or len(ram[0][key].data)!=1 or len(saved[0][key].data)!=1:
            raise ValueError("Invalid base-look descriptor/value")
        fields.append(dict(slot=slot,key=key,before_ram=ram[0][key].data.hex(),before_saved=saved[0][key].data.hex(),after="00"))
        for i in range(8):
            row=descriptor(0x1520+i*18+selector);base=descriptor(0x1520+i*18);key=row[1]
            value=ram[0][base[1]].data
            if row[0]!=0 or row[2]!=0x40000 or len(value)!=4 or len(ram[0][key].data)!=4 or len(saved[0][key].data)!=4:
                raise ValueError("Invalid adjustment descriptor/value")
            fields.append(dict(slot=slot,key=key,before_ram=ram[0][key].data.hex(),before_saved=saved[0][key].data.hex(),after=value.hex()))
    if len(fields)!=54 or len({f["key"] for f in fields})!=54 or any(f["before_ram"]!=f["before_saved"] for f in fields):
        raise ValueError("Selected recipes differ in RAM/storage; preserve this checkpoint")
    devicesettings.require_save_preserves_unsaved(ram,saved,{f["key"] for f in fields})
    return fields


def main():
    if os.geteuid()!=0:
        raise PermissionError("Use sudo in your terminal for Mac USB capture")
    os.umask(0o077)
    package=Package(WORKSPACE)
    diagnostic=json.loads((ROOT/"private/runtime-diagnostic/runtime.private.json").read_text())
    if not diagnostic["simulation_passed"]:
        raise ValueError("Read-only diagnostic has not passed native simulation")
    spec=diagnostic["worker"];blob=(ROOT/spec["file"]).read_bytes()
    if len(blob)!=spec["bytes"] or sha(blob)!=spec["sha256"]:
        raise ValueError("Reviewed read-only diagnostic changed")
    parent=ROOT/"private/lut-checkpoints"
    parent.mkdir(parents=True,exist_ok=True);private_owner(parent,True)
    stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    folder=parent/("six-before-"+stamp)
    folder.mkdir(exist_ok=False);private_owner(folder,True)
    job=Job(package,folder)
    serial=package.binding["usb_serial_sha256"]
    body=sha(("ILCE-7CR\0"+serial).encode())
    store_roots=[ROOT/"private/lut-backups-a",ROOT/"private/lut-backups-b"]
    stores=[backupstore.Store(p,body) for p in store_roots]
    files={}
    def capture(name,raw):
        specs=[store.put(name,raw) for store in stores]
        if specs[0]!=specs[1] or any(store.read(spec)!=raw for store,spec in zip(stores,specs)):
            raise ValueError("Independent checkpoint reconstruction differs")
        files[name]=specs[0]
        durable_json(folder/"checkpoint.partial.private.json",dict(schema="a7cr-lut-checkpoint/1",body_binding=package.binding,
            body_key=body,stores=[str(p.relative_to(ROOT)) for p in store_roots],files=files,complete=False))
        job.record("two_checkpoint_copies_verified",file=name,bytes=len(raw),sha256=sha(raw))
    def snapshots(camera,tag):
        result={}
        for memory,name in ((True,"memory"),(False,"flash")):
            raw=camera.snapshot(memory);capture(tag+"-"+name,raw)
            sections=backup_sections(raw)
            serial_raw=sections[0][0x00e70003].data
            if len(serial_raw)!=4 or sha(serial_raw.hex().encode("ascii"))!=package.binding["ap_serial_sha256"]:
                raise ValueError("AP backup identity differs")
            for key in CP_UNITS:
                expected=package.units["candidate"].get(key,package.protected.get(key))
                if sections[1][key].data!=expected:
                    raise ValueError("Protected CP unit differs from completed FL23 installation")
            result[name]=sections
        return result
    try:
        with (ROOT/"private/device.lock").open("a") as lock:
            fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            with CheckpointSession(package,job.record) as camera:
                job.body(camera)
                programs={}
                for kind,path in PATHS.items():
                    raw=camera.read_program(path)
                    if raw!=package.programs["candidate"][kind]:
                        capture("unexpected-"+kind,raw)
                        raise ValueError("Current complete programs differ from reviewed FL23 source")
                    capture(kind,raw);programs[kind]=raw
                initial=snapshots(camera,"before")
                fields=settings_plan(programs["AP"],initial["memory"],initial["flash"])
                name_plans=[]
                print("读取 68 个原始菜单资源并验证两份压缩备份；不写入相机。",flush=True)
                for index,name in enumerate(RESOURCE_NAMES):
                    raw=camera.read_resource(name);capture("resource/"+name,raw)
                    changed,plan=resources.rename(raw,dict(enumerate(NAMES,1)),list(range(0x0200ab2c,0x0200ab32)))
                    if resources.inverse(changed,plan)!=raw:
                        raise ValueError("Fresh resource inverse differs")
                    name_plans.append(dict(file=name,before_sha256=sha(raw),after_sha256=sha(changed),before_bytes=len(raw),after_bytes=len(changed)))
                    if (index+1)%17==0: print(f"菜单资源备份：{index+1}/68",flush=True)
                for key in (0x02a40001,0x02a4000d):
                    if camera.required_cp_read(key)!=initial["memory"][1][key].data:
                        raise ValueError("Direct CP read differs from complete snapshot")
                runtime=runtime_invoke(camera,blob,diagnostic["spans"],package,folder,job.record)
                if not runtime["ok"] or not runtime["all_loaded_ap_spans_match_candidate"]:
                    raise ValueError("Running AP differs from current FL23 disk source; preserve diagnostic")
                final=snapshots(camera,"after")
                preservation={source:preserved(initial[source],final[source],{}) for source in initial}
        checkpoint=dict(schema="a7cr-lut-checkpoint/1",body_binding=package.binding,body_key=body,
            stores=[str(p.relative_to(ROOT)) for p in store_roots],files=files,complete=True,
            utc=datetime.now(timezone.utc).isoformat(),resource_count=68,settings=fields,names=name_plans,
            loaded_ap=runtime,preservation=preservation,parameters=parameter_report(package,final),
            firmware_resource_settings_or_wbi_written=False,normal_usb_return_confirmed=True,
            same_physical_mac_volume=True)
        durable_json(folder/"checkpoint.private.json",checkpoint)
        job.record("READONLY_SIX_CHECKPOINT_CREATED",file_count=len(files),firmware_written=False)
        print(json.dumps(dict(phase="READONLY_SIX_CHECKPOINT_CREATED",checkpoint=str(folder),
            resource_files=68,verified_reconstructable_copies=2,loaded_ap_matches_fl23=True,
            firmware_resource_settings_or_wbi_written=False),indent=2),flush=True)
    except BaseException as error:
        job.record("stopped_no_retry",error_type=type(error).__name__,error=str(error))
        print("只读检查已停止；保留输出，不要自动重复命令。",flush=True)
        raise
    finally:
        # Sudo owns newly compressed objects initially. Return private local
        # files to the invoking account so later offline builds can read them.
        for root in store_roots:
            if root.exists():
                private_owner(root,True)
                for path in root.rglob("*"):
                    private_owner(path,path.is_dir())


if __name__=="__main__":
    main()
