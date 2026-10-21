"""Build a read-only S1 preflight and a reviewed AP-only completion plan."""
from __future__ import annotations
import json
import sys
from build_native_workers import ROOT,compile_worker,source,manifest_header,sha
from inspect_sources import save_json
sys.path.insert(0,str(ROOT/'device'))
from install_six_luts import Package
from complete_six_luts import review_inspection


def main():
    p=Package();reviewed,current=review_inspection(p)
    folder=p.root/'completion'
    if (folder/'completion.private.json').exists():raise ValueError('Do not overwrite a prepared completion plan')
    folder.mkdir(exist_ok=True)
    initial=[sha(p.states['cp_only'][k]) for k in ('AP','CP')]
    final=[sha(p.states['installed'][k]) for k in ('AP','CP')]
    sizes=[len(p.states['cp_only'][k]) for k in ('AP','CP')]
    windows=p.audit['programs']['AP']['windows']
    if any(w['chip']!=0 for w in windows):raise ValueError('Completion check may not have CP write windows')
    text=source('program',True)
    if sha(text.encode())!=p.manifest['workers']['program_check']['source_sha256']:
        raise ValueError('Reviewed check-only worker algorithm changed')
    worker=compile_worker(folder/'check','completion-check-only',text,manifest_header(initial,final,sizes,windows))
    if (worker['bytes']+4)%512==0:raise ValueError('Worker would hit the terminal response boundary')
    audit={'programs':{k:{'source_sha256':initial[i],'bytes':sizes[i]} for i,k in enumerate(('AP','CP'))}}
    plan=dict(schema='a7cr-six-ap-completion/1',body_binding=p.binding,inspection_review=reviewed,
        program_check=worker,check_audit=audit,native_simulation_passed=False,host_tests_passed=False,
        normal_usb_confirmed_after_timeout=False,cp_write_windows=0,resource_replacement_operations=0,
        remaining_writes=['Nine AP windows','Selected six-slot fields only; SAVE3(02cf) if needed','WBI drop once and mode 2 to 0'],
        original_failure_and_usb_timeout_preserved=True)
    save_json(folder/'completion.private.json',plan)
    print(json.dumps(dict(check_worker_bytes=worker['bytes'],ap_windows=len(windows),cp_write_windows=0,
        resources_verified=68,historical_changes={k:len(v) for k,v in reviewed['historical_unselected_changes_preserved'].items()}),indent=2))


if __name__=='__main__':main()
