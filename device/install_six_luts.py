"""One body-bound six-look installation; fresh checks, durable phases, no retry."""
from __future__ import annotations

import argparse
from datetime import datetime,timezone
import fcntl
import json
import os
from pathlib import Path
import struct

from prepare_six_luts import CheckpointSession,settings_plan,RESOURCE_NAMES
from diagnose_fl23 import invoke as runtime_invoke
from fl23_install import Package as Fl23Package,Job as Fl23Job,OWNED,PATHS,invoke as program_invoke,durable_json,store_private,preserved
from preflight_fl23 import sha
from read_backup import ROOT,backup_sections,private_owner,CP_UNITS
from looktool.backupstore import Store
from looktool import resources,nameworker,devicesettings
import resource_mirror

JOB=ROOT/'private/lut-install/six-20261020-01'
NAME_TEMPS=frozenset(('a7cr.six.names.so','a7c2.names.request','a7c2.names.result'))


def selected_preservation(before,after,fields):
    """Verify exactly the reviewed LUT fields, then all unselected scope.

    The original FL23 comparator permits only FL23 targets. Neutralizing
    already-verified selected fields reuses its full unselected/layout checks
    without broadening the original installer's write permissions.
    """
    neutral=[dict(after[0]),after[1]];keys=set()
    for field in fields:
        key=field['key'];value=bytes.fromhex(field['after'])
        if key in keys or key>>16!=0x02cf or key==0x02cf0b6e:
            raise ValueError('Selected preservation target is not unique/writable')
        keys.add(key)
        old,new=before[0][key],after[0][key]
        if new.data!=value or new.attr!=old.attr:
            raise ValueError(f'Selected saved field differs: {key:08x}')
        neutral[0][key]=old
    report=preserved(before,neutral,{})
    report['preserved_properties']-=len(keys)
    report['selected_fields_verified']=len(keys)
    return report


class Package:
    def __init__(self,root=JOB):
        self.root=root.resolve()
        self.manifest=json.loads((self.root/'package.private.json').read_text())
        m=self.manifest
        if m['schema']!='a7cr-six-installation/1' or m['model']!='ILCE-7CR' or m['version']!='2.01':
            raise ValueError('Unknown six-look package')
        checkpoint=(ROOT/m['checkpoint']).resolve()
        raw=(checkpoint/'checkpoint.private.json').read_bytes()
        if sha(raw)!=m['checkpoint_sha256']:raise ValueError('Checkpoint changed')
        self.checkpoint=json.loads(raw);self.binding=m['body_binding']
        if not self.checkpoint['complete'] or self.checkpoint['body_binding']!=self.binding:
            raise ValueError('Checkpoint body binding differs')
        self.stores=[Store(ROOT/p,m['body_key']) for p in m['stores']]
        if len(self.stores)!=2 or self.stores[0].root==self.stores[1].root:
            raise ValueError('Independent checkpoint stores are required')
        self.blobs={}
        for name,spec in m['workers'].items():
            raw=(ROOT/spec['file']).read_bytes()
            if sha(raw)!=spec['sha256'] or len(raw)!=spec['bytes'] or len(raw)>65536:
                raise ValueError('Prepared worker changed: '+name)
            self.blobs[name]=raw
        original={k:self.source(k) for k in PATHS};candidate={}
        for kind,old in original.items():
            spec=m['programs'][kind];target=bytearray(old);end=0
            if sha(old)!=spec['source_sha256'] or len(old)!=spec['bytes']:
                raise ValueError('Checkpoint program identity differs')
            for w in spec['windows']:
                at,n=w['offset'],w['bytes'];before,after=bytes.fromhex(w['before_hex']),bytes.fromhex(w['after_hex'])
                if at<end or not 0<n<=4096 or len(before)!=n or len(after)!=n or old[at:at+n]!=before:
                    raise ValueError('Prepared program window differs')
                target[at:at+n]=after;end=at+n
            candidate[kind]=bytes(target)
            if sha(candidate[kind])!=spec['candidate_sha256']:
                raise ValueError('Prepared target identity differs')
            inverse=bytearray(candidate[kind])
            for w in spec['windows']:inverse[w['offset']:w['offset']+w['bytes']]=bytes.fromhex(w['before_hex'])
            if inverse!=old:raise ValueError('Complete program inverse differs')
        self.programs={'original':original,'candidate':candidate}
        self.states={'original':original,'cp_only':dict(AP=original['AP'],CP=candidate['CP']),'installed':candidate}
        self.audit={'programs':m['programs']}
        self.fl23=Fl23Package(ROOT/'private/install/20261020-a7cr-fl23-01')
        if self.fl23.binding!=self.binding or self.fl23.programs['candidate']!=original:
            raise ValueError('Completed FL23/body source differs')
        self.protected=self.fl23.protected
        self.units=self.fl23.units
        self.fields=m['settings'];self.names={int(k):v for k,v in m['names'].items()}
        if len(self.fields)!=54 or len({f['key'] for f in self.fields})!=54 or set(self.names)!=set(range(1,7)):
            raise ValueError('Six-slot settings/title plan differs')
        self.resources={name:self.source('resource/'+name) for name in RESOURCE_NAMES}
        self.named_resources={}
        for name,raw in self.resources.items():
            changed,plan=resources.rename(raw,self.names,list(range(0x0200ab2c,0x0200ab32)))
            if resources.inverse(changed,plan)!=raw:raise ValueError('Resource inverse differs')
            self.named_resources[name]=changed

    def source(self,name):
        spec=self.manifest['files'][name];copies=[s.read(spec) for s in self.stores]
        if copies[0]!=copies[1]:raise ValueError('Checkpoint reconstructions disagree')
        return copies[0]


class Session(CheckpointSession):
    def __init__(self,package,record):
        super().__init__(package,record);self.package=package
        self.expected_usb_serial_sha256=package.binding['usb_serial_sha256']

    def select_temp(self,name):
        if name in NAME_TEMPS|resource_mirror.TEMP:
            status,_=self.temp_command(15,b'\0/tmp/jiritsu/'+name.encode()+b'\0')
            if status:self.healthy=False;raise ValueError('Native title path selection failed')
        else:super().select_temp(name)

    def read_resource(self,filename):
        if filename not in RESOURCE_NAMES:raise ValueError('Resource is not allowlisted')
        if filename==resource_mirror.RESOURCE:
            if not hasattr(self,'mirror_context'):raise ValueError('A per-attempt mirror evidence path is required')
            return resource_mirror.read(self,self.package,*self.mirror_context)
        self.jiritsu(15,b'\0/tmp/jiritsu/../../usr/share/app/'+filename.encode('ascii')+b'\0')
        raw=self.jiritsu(17,b'\0\xff\0');parsed=resources.decode(raw)
        if not 5740<=len(raw)<=524288 or parsed['group']!=5 or parsed['count'] not in (2860,2866):
            raise ValueError('Resource structure differs')
        return raw

    def write_selected(self,key,value):
        allowed={f['key']:bytes.fromhex(f['after']) for f in self.package.fields}
        if key not in allowed or value!=allowed[key] or key>>16!=0x02cf or key==0x02cf0b6e:
            raise ValueError('Write is outside reviewed six-slot fields')
        return self.call(f'WRITE2_SELECTED_{key:08x}',self.camera.writeBackup,key,value)

    def save_selected(self):
        return self.call('SAVE3_SELECTED_02cf',self.camera.saveBackup,0x02cf)


class Job(Fl23Job):
    def capture(self,name,raw):
        specs=[store.put(name,raw) for store in self.package.stores]
        if specs[0]!=specs[1] or any(s.read(spec)!=raw for s,spec in zip(self.package.stores,specs)):
            raise ValueError('New checkpoint reconstruction differs')
        self.record('incremental_readback_backed_up',file=name,spec=specs[0])

    def snapshots(self,camera,tag):
        result={}
        for memory,name in ((True,'memory'),(False,'flash')):
            raw=camera.snapshot(memory);self.capture('six-'+tag+'-'+name,raw);sections=backup_sections(raw)
            serial=sections[0][0x00e70003].data
            if len(serial)!=4 or sha(serial.hex().encode('ascii'))!=self.package.binding['ap_serial_sha256']:
                raise ValueError('Fresh AP identity differs')
            for key in CP_UNITS:
                expected=self.package.fl23.units['candidate'].get(key,self.package.protected.get(key))
                if sections[1][key].data!=expected:raise ValueError('Protected CP unit differs')
            result[name]=sections
        return result

    def program_state(self,camera,tag,expected=None):
        result=super().program_state(camera,tag,expected)
        if expected in ('cp_only','installed'):
            for kind,raw in self.package.states[expected].items():self.capture(kind,raw)
        return result

    def titles(self,camera,named):
        camera.mirror_context=(self.attempt,self.record)
        expected=self.package.named_resources if named else self.package.resources
        for name,raw in expected.items():
            actual=camera.read_resource(name)
            if actual!=raw:
                self.capture('unexpected-resource/'+name,actual)
                raise ValueError('Complete resource readback differs: '+name)
        self.record('complete_resource_readback',count=68,named=named)

    def names_native(self,camera,mode):
        if mode not in (0,1,2,3):raise ValueError('Invalid title mode')
        blob=self.package.blobs['names_stage']
        expected={'a7cr.six.names.so':blob,'libJit.so':blob,'a7c2.names.request':struct.pack('<8sII',b'A7NAM001',mode,0)}
        for name in OWNED|NAME_TEMPS:
            if camera.read_temp(name,True) is not None:raise ValueError('Preserve previous native temporary result')
        camera.check_preload()
        for name in ('a7cr.six.names.so','a7c2.names.request'):
            camera.write_temp(name,expected[name],expected)
            if camera.read_temp(name)!=expected[name]:raise ValueError('Title worker staging differs')
        self.record('names_native_invocation_intent',mode=mode)
        try:
            camera.write_temp('libJit.so',blob,expected)
            raw=camera.read_temp('a7c2.names.result');store_private(self.attempt/f'names-mode{mode}.private.bin',raw)
            parsed=nameworker.validate(raw,mode,self.package.manifest['names_build'])
        except BaseException:
            camera.healthy=False;raise
        expected['a7c2.names.result']=raw
        self.record('names_native_invocation_returned',mode=mode,report=parsed)
        for name in ('libJit.so','a7c2.names.result','a7c2.names.request','a7cr.six.names.so'):
            camera.remove_temp(name,expected)
        return parsed

    def install(self,camera):
        self.body(camera);self.program_state(camera,'initial','original')
        initial=self.snapshots(camera,'initial')
        fresh=settings_plan(self.package.programs['original']['AP'],initial['memory'],initial['flash'])
        if fresh!=self.package.fields:raise ValueError('Selected recipes or ST source changed since preparation')
        self.titles(camera,False)
        diagnostic=json.loads((ROOT/'private/runtime-diagnostic/runtime.private.json').read_text())
        spec=diagnostic['worker'];blob=(ROOT/spec['file']).read_bytes()
        if not diagnostic['simulation_passed'] or sha(blob)!=spec['sha256']:
            raise ValueError('Reviewed loaded-AP diagnostic changed')
        live=runtime_invoke(camera,blob,diagnostic['spans'],self.package.fl23,self.attempt,self.record)
        if not live['ok'] or not live['all_loaded_ap_spans_match_candidate']:
            raise ValueError('Running FL23 AP does not match the prepared source')
        self.native(camera,'program_check',0)
        self.names_native(camera,0)
        self.native(camera,'wbi_check',0)
        before=self.snapshots(camera,'before-write')
        for source in initial:preserved(initial[source],before[source],{})
        self.phase('NATIVE_PREFLIGHT_PASSED')
        self.phase('CP_PROGRAM_WRITE_INTENT');self.native(camera,'cp_stage',1)
        self.program_state(camera,'after-cp','cp_only');self.phase('CP_PROGRAM_VERIFIED')
        self.phase('TITLE_RESOURCES_WRITE_INTENT');self.names_native(camera,1)
        self.titles(camera,True);self.phase('TITLE_RESOURCES_VERIFIED')
        self.phase('AP_PROGRAM_WRITE_INTENT');self.native(camera,'ap_stage',1)
        self.program_state(camera,'after-ap','installed');self.phase('AP_PROGRAM_VERIFIED')
        self.phase('SELECTED_RECIPES_WRITE_INTENT')
        changed=False
        for f in self.package.fields:
            value=bytes.fromhex(f['after'])
            if before['memory'][0][f['key']].data!=value:
                camera.write_selected(f['key'],value);changed=True
        if changed:camera.save_selected()
        after=self.snapshots(camera,'after-selected')
        for source in after:
            report=selected_preservation(before[source],after[source],self.package.fields)
            self.record('selected_saved_settings_and_preservation_verified',source=source,**report)
        self.phase('PROGRAMS_RESOURCES_SELECTED_SETTINGS_VERIFIED')
        self.native(camera,'wbi_stage',1)
        self.phase('WBI_INVALIDATED_VERIFIED')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--battery-percent',type=int,required=True)
    args=parser.parse_args()
    if os.geteuid()!=0:raise PermissionError('Use sudo in your terminal for Mac USB capture')
    if not 75<=args.battery_percent<=100:raise ValueError('Use a freshly confirmed battery level of at least 75 percent')
    os.umask(0o077);package=Package()
    if not package.manifest['native_worker_simulation_passed'] or not package.manifest['host_flow_tests_passed']:
        raise ValueError('Installation worker/host-flow tests have not passed')
    with (ROOT/'private/device.lock').open('a') as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        state=json.loads((package.root/'state.private.json').read_text())
        if state['phase']!='PREPARED_NOT_INSTALLED':raise ValueError('An attempt already exists; inspect it without replaying writes')
        stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        attempt=package.root/('install-'+stamp);attempt.mkdir(exist_ok=False);private_owner(attempt,True)
        job=Job(package,attempt)
        try:
            job.phase('INSTALL_ATTEMPT_OPENED',battery_percent=args.battery_percent)
            with Session(package,job.record) as camera:job.install(camera)
            job.phase('INSTALLED_PENDING_COLD_START',firmware_written=True)
            print(json.dumps(dict(phase='INSTALLED_PENDING_COLD_START',attempt=str(attempt),slots=package.names),indent=2,ensure_ascii=False),flush=True)
            print('全部写入和读回已结束。现在可拔 USB、正常关机，等存取灯熄灭后取出电池至少60秒，再装回开机。',flush=True)
        except BaseException as error:
            job.phase('STOPPED_INSPECTION_REQUIRED',error_type=type(error).__name__,error=str(error))
            print('已停止，未自动重试。请保留输出和连接，不要重复安装、关机或取电池；先检查当前状态。',flush=True)
            raise
        finally:
            for store in package.stores:
                root=store.root.parent
                for path in [root,*root.rglob('*')]:private_owner(path,path.is_dir())


if __name__=='__main__':main()
