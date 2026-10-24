"""Check the AP-only source state; use synthetic files/syscalls, never USB."""
from __future__ import annotations
import json
from check_native_workers import Machine,AP,CP,program_files,program_report
from build_native_workers import ROOT,compile_worker,source,manifest_header,sha
from inspect_sources import save_json


def main():
    folder=ROOT/'private/lut-install/six/completion'
    path=folder/'completion.private.json';plan=json.loads(path.read_text())
    manifest=json.loads((folder.parent/'package.private.json').read_text())
    text=source('program',True)
    if plan['program_check']['source_sha256']!=sha(text.encode()):raise ValueError('Actual completion check uses another algorithm')
    old=bytearray(20000);new=bytearray(old);windows=[];at=256
    for row in manifest['programs']['AP']['windows']:
        a,b=bytes.fromhex(row['before_hex']),bytes.fromhex(row['after_hex']);n=len(a)
        old[at:at+n]=a;new[at:at+n]=b
        windows.append(dict(offset=at,bytes=n,before_hex=a.hex(),after_hex=b.hex(),chip=0));at=(at+n+63)&~63
    before=(bytes(old),b'CP already installed\0'*512);after=(bytes(new),before[1])
    spec=compile_worker(folder/'simulation','completion-check-only',text,
        manifest_header(list(map(sha,before)),list(map(sha,after)),list(map(len,before)),windows))
    blob=(ROOT/spec['file']).read_bytes();rows=[]
    for name,mode,files,options,success in [('current-cp-only-source',0,before,{},True),
        ('reject-install-mode',1,before,{},False),('reject-inverse-mode',2,before,{},False),
        ('reject-wrong-current-cp',0,(before[0],before[1][:-1]+b'x'),{},False),
        ('reject-already-target-ap',0,after,{},False),('short-read-reassembly',0,before,{'short_reads':True},True),
        ('reject-non-root',0,before,{'uid':501},False)]:
        m=Machine(blob,program_files(*files,mode),**options);m.run();report=program_report(m)
        if (report['status']==0)!=success or (bytes(m.files[AP]),bytes(m.files[CP]))!=files:
            raise ValueError('Completion check outcome differs: '+name)
        if m.program_writes or 40 in m.calls or 68 in m.calls:raise ValueError('Check-only completion worker mutated program/mount state')
        rows.append(dict(case=name,passed=True))
    plan['native_simulation_passed']=True
    save_json(folder/'simulation.private.json',dict(results=rows,camera_access=False,passed=True))
    save_json(path,plan)
    print(json.dumps(dict(completion_check_native_cases=len(rows),camera_access=False)))


if __name__=='__main__':main()
