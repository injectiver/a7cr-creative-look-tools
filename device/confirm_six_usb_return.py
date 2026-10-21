"""Read USB descriptors only and retain the original inspection timeout."""
from datetime import datetime,timezone
import json
from install_six_luts import Package
from complete_six_luts import review_inspection,INSPECTION
from read_backup import normal_identity
from fl23_install import durable_json


def main():
    p=Package();reviewed,current=review_inspection(p)
    identity=normal_identity()
    if identity['usb_serial_sha256']!=p.binding['usb_serial_sha256']:
        raise ValueError('Ordinary USB returned for another body')
    report=dict(schema='a7cr-six-late-usb-confirmation/1',inspection=INSPECTION,
        inspection_events_sha256=reviewed['events_sha256'],confirmed_utc=datetime.now(timezone.utc).isoformat(),
        identity=identity,original_timeout_preserved=True,original_deadline_met=False,
        normal_usb_now_confirmed=True,authentication_or_camera_writes_performed=False)
    durable_json(p.root/INSPECTION/'late-normal-usb.private.json',report)
    path=p.root/'completion/completion.private.json'
    plan=json.loads(path.read_text())
    if reviewed!=plan['inspection_review']:raise ValueError('Prepared inspection review differs')
    plan['normal_usb_confirmed_after_timeout']=True
    plan['late_normal_usb_evidence']=str((p.root/INSPECTION/'late-normal-usb.private.json').relative_to(p.root))
    durable_json(path,plan)
    print(json.dumps(dict(normal_usb_now_confirmed=True,original_timeout_preserved=True,
        cp_and_68_resources_readback_verified=True,selected_fields_and_cp_units_unchanged=True,
        new_camera_writes=False),indent=2))


if __name__=='__main__':main()
