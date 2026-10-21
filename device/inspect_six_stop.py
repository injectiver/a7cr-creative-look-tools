"""Inspect the exact reviewed CP+names-complete stop without repeating writes.

Use the original service device and sequence, or explicitly request a fresh
ordinary MSC session after the old service ended. Never fall back or retry.
No program/resource/settings/WBI writes. One fixed resource is copied to an
owned padded temporary file for a full independent readback.
"""
from __future__ import annotations
from datetime import datetime,timezone
import fcntl
import argparse
import json
import os
from pathlib import Path
import struct
import time

from install_six_luts import Package,Session,Job,ROOT,NAME_TEMPS,RESOURCE_NAMES
from fl23_install import decode_stage,durable_json,preserved
from preflight_fl23 import sha,decode_program,decode_wbi
from read_backup import usb_modules,private_owner,backup_sections
from looktool import nameworker
import resource_mirror

FAILED='install-20261020T132637444333Z'


def review(package):
    state=json.loads((package.root/'state.private.json').read_text())
    if state.get('phase')!='STOPPED_INSPECTION_REQUIRED' or state.get('attempt')!=FAILED or state.get('error_type')!='GenericUsbException':
        raise ValueError('This command is bound only to the reviewed resource-read timeout')
    folder=package.root/FAILED
    raw=(folder/'events.private.json').read_bytes();events=json.loads(raw)
    expected=[('program_check',0),('wbi_check',0),('cp_stage',1)]
    if [(e['worker'],e['mode']) for e in events if e['phase']=='native_invocation_intent']!=expected:
        raise ValueError('AP/WBI write or another program operation was attempted')
    if [e['mode'] for e in events if e['phase']=='names_native_invocation_intent']!=[0,1]:
        raise ValueError('Unexpected title operation history')
    if any(e.get('operation','').startswith(('WRITE2_','WRITE41_','SAVE3_')) for e in events):
        raise ValueError('Settings writes were already attempted')
    if not decode_stage((folder/'cp_stage-mode1.private.bin').read_bytes(),'cp_stage',1,package)['ok']:
        raise ValueError('Native CP completion was not established')
    if not decode_program((folder/'program_check-mode0.private.bin').read_bytes(),package.audit)['ok'] or not decode_wbi((folder/'wbi_check-mode0.private.bin').read_bytes())['ok']:
        raise ValueError('Captured native preflight did not pass')
    for mode in (0,1):nameworker.validate((folder/f'names-mode{mode}.private.bin').read_bytes(),mode,package.manifest['names_build'])
    readback={e['chip']:e for e in events if e['phase']=='complete_program_byte_readback' and e['tag']=='after-cp'}
    if set(readback)!=set(package.states['cp_only']) or any(readback[k]['sha256']!=sha(v) for k,v in package.states['cp_only'].items()):
        raise ValueError('Full post-CP program readback is not established')
    i=next(i for i,e in enumerate(events) if e['phase']=='names_native_invocation_returned' and e['mode']==1)
    start=next(j for j in range(i+1,len(events)) if events[j]['phase']=='read_intent' and events[j].get('operation')=='JIRITSU_15')
    tail=events[start:]
    complete=sum(e['phase']=='read_returned' and e.get('operation')=='JIRITSU_17' for e in tail)
    if complete!=9 or RESOURCE_NAMES[complete]!=resource_mirror.RESOURCE or tail[-2].get('operation')!='JIRITSU_17':
        raise ValueError('Interrupted resource is not the reviewed terminal packet boundary')
    if (len(package.named_resources[resource_mirror.RESOURCE])+4)%512:
        raise ValueError('Expected aligned response layout differs')
    before={}
    for name in ('memory','flash'):
        capture=next(e for e in events if e['phase']=='incremental_readback_backed_up' and e['file']=='six-before-write-'+name)
        copies=[s.read(capture['spec']) for s in package.stores]
        if copies[0]!=copies[1]:raise ValueError('Failed-attempt baseline backups differ')
        before[name]=backup_sections(copies[0])
    original=next(e['identity'] for e in events if e['phase']=='normal_authentication_intent')
    port=next(e for e in events if e['phase']=='usb_transition_observed' and any(x['pid']=='0336' for x in e['devices']))
    port=next(x for x in port['devices'] if x['pid']=='0336')
    returned=[e for e in events if e['phase']=='read_returned']
    if set(e['operation'] for e in returned)-{'JIRITSU_15','JIRITSU_17','PREFLIGHT_TEMP_15','PREFLIGHT_TEMP_16','PREFLIGHT_TEMP_17','PREFLIGHT_TEMP_18','BACKUP_READ_MEMORY','BACKUP_READ_FLASH'}:
        raise ValueError('Cannot reconstruct the service packet sequence')
    report=dict(schema='a7cr-reviewed-six-stop/1',failed_attempt=FAILED,events_sha256=sha(raw),
        native_cp_committed_and_host_readback_verified=True,native_all_68_resources_committed_verified_readonly=True,
        independent_resources_verified_before_stop=complete,interrupted_resource=resource_mirror.RESOURCE,
        ap_settings_wbi_write_attempted=False,next_sequence=len(returned)+2,
        port=dict(bus=port['bus'],ports=port['ports']),normal_identity=original)
    return report,before


class ExistingService(Session):
    def __init__(self,package,record,reviewed):
        super().__init__(package,record);self.reviewed=reviewed
    def __enter__(self):
        from pmca.usb.driver.generic import GenericUsbDriver
        from pmca.usb.driver.generic.libusb import UsbBackend
        from pmca.usb.sony import SonySenserDevice,SonySenserCamera,SonySenserAuthDevice
        usb,backend=usb_modules();self.usb=usb
        found=list(usb.core.find(find_all=True,idVendor=0x054c,idProduct=0x0336,backend=backend))
        if len(found)!=1:raise ValueError('The original service device is not present; no authentication fallback')
        self.device=found[0];self.location=(self.device.bus,tuple(self.device.port_numbers or ()))
        wanted=self.reviewed['port']
        if self.location!=(wanted['bus'],tuple(wanted['ports'])):
            usb.util.dispose_resources(self.device);raise ValueError('Service device is on another USB port')
        if self.device.is_kernel_driver_active(0):
            usb.util.dispose_resources(self.device);raise ValueError('Unexpected service kernel driver; no detach/reset')
        class Bounded(UsbBackend):
            def __del__(inner):pass
            def reset(inner):inner.deadline=time.monotonic()+getattr(inner,'operation_budget_seconds',20)
            def timeout(inner,requested=None):
                left=int((inner.deadline-time.monotonic())*1000)
                if left<=0:raise TimeoutError('Existing-service read exceeded its budget')
                return min(left,requested or 20000)
            def read(inner,ep,n,timeout=None):return super().read(ep,n,inner.timeout(timeout))
            def write(inner,ep,data):
                inner.dev.default_timeout=inner.timeout();return super().write(ep,data)
        try:
            usb.util.claim_interface(self.device,0)
            self.backend=Bounded(self.device);driver=GenericUsbDriver(self.backend)
            self.channel=SonySenserDevice(driver);self.channel._sequence=self.reviewed['next_sequence']
            self.camera=SonySenserCamera(self.channel)
            self.identity=self.reviewed['normal_identity']
            self.auth=SonySenserAuthDevice(driver)
            self.record('existing_service_attached_no_authentication',bus=self.location[0],ports=list(self.location[1]),next_sequence=self.channel._sequence)
            serial=self.call('RECOVERY_READ_AP_SERIAL',self.camera.readBackup,0x00e70003)
            if len(serial)!=4 or sha(serial.hex().encode('ascii'))!=self.package.binding['ap_serial_sha256']:
                raise ValueError('Existing service AP body identity differs')
            self.record('existing_service_body_binding_verified',authentication_repeated=False)
            return self
        except BaseException:
            self.healthy=False;usb.util.dispose_resources(self.device);raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--normal',action='store_true',help='Explicit fresh ordinary MSC session after descriptors confirm the previous service ended; no fallback or repeated authentication.')
    args=parser.parse_args()
    if os.geteuid()!=0:raise PermissionError('Use sudo in your terminal for Mac USB capture')
    os.umask(0o077);p=Package();reviewed,before=review(p)
    manifest=json.loads(resource_mirror.MANIFEST.read_text())
    if not manifest['simulation_passed']:raise ValueError('Read-only resource workaround has not passed simulation')
    with (ROOT/'private/device.lock').open('a') as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        folder=p.root/('inspect-stop-'+stamp);folder.mkdir(exist_ok=False);private_owner(folder,True)
        job=Job(p,folder)
        try:
            durable_json(folder/'reviewed-failure.private.json',reviewed)
            context=Session(p,job.record) if args.normal else ExistingService(p,job.record,reviewed)
            with context as camera:
                job.body(camera)
                print('核对已结束的写入和当前机身；不重复写入 CP、菜单或设置。',flush=True)
                job.program_state(camera,'stop-inspection','cp_only')
                print('读取 68 个已写入菜单文件；边界文件使用只读临时副本。',flush=True)
                job.titles(camera,True)
                current=job.snapshots(camera,'stop-inspection')
                reports={source:preserved(before[source],current[source],{}) for source in current}
            result=dict(schema='a7cr-six-stop-inspection/1',phase='CP_AND_NAMES_VERIFIED_AP_PENDING',
                failed_attempt=FAILED,failed_events_sha256=reviewed['events_sha256'],program_state='cp_only',
                full_resources_verified=68,selected_settings_still_before_install=True,
                preservation=reports,normal_usb_return_confirmed=True,
                firmware_resources_settings_or_wbi_written=False,repeated_authentication=False,
                explicit_fresh_normal_session=args.normal,service_authentication_performed=args.normal)
            durable_json(folder/'inspection.private.json',result)
            print(json.dumps(dict(phase=result['phase'],inspection=str(folder),full_resources_verified=68,
                firmware_resources_settings_or_wbi_written=False),indent=2),flush=True)
        except BaseException as error:
            job.record('inspection_stopped_no_retry',error_type=type(error).__name__,error=str(error))
            print('只读核验已停止；保留输出和连接，不重试、不关机。',flush=True);raise
        finally:
            for store in p.stores:
                root=store.root.parent
                for path in [root,*root.rglob('*')]:private_owner(path,path.is_dir())


if __name__=='__main__':main()
