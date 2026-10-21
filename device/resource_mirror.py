"""Read the one aligned resource through a checked padded temporary copy."""
from __future__ import annotations
import json
import struct
import uuid
from fl23_install import ROOT,store_private
from preflight_fl23 import sha

RESOURCE='string_croatian_vertical.uxc'
TEMP=frozenset(('a7cr.six.boundary.so','a7cr.six.boundary.data','a7cr.six.boundary.result'))
MANIFEST=ROOT/'private/lut-install/six-20261020-01/resource-mirror/mirror.private.json'


def read(camera,package,folder,record):
    m=json.loads(MANIFEST.read_text());spec=m['worker'];blob=(ROOT/spec['file']).read_bytes()
    if not m['simulation_passed'] or m['resource']!=RESOURCE or sha(blob)!=spec['sha256'] or len(blob)!=spec['bytes']:
        raise ValueError('Read-only resource mirror is not validated')
    for name in TEMP|{'libJit.so'}:
        if camera.read_temp(name,True) is not None:raise ValueError('Preserve previous mirror temporary results')
    camera.check_preload();expected={'a7cr.six.boundary.so':blob,'libJit.so':blob}
    camera.write_temp('a7cr.six.boundary.so',blob,expected)
    if camera.read_temp('a7cr.six.boundary.so')!=blob:raise ValueError('Staged mirror module differs')
    record('readonly_resource_mirror_intent',resource=RESOURCE,persistent_source_writes=False)
    try:
        camera.write_temp('libJit.so',blob,expected)
        report=camera.read_temp('a7cr.six.boundary.result')
        if len(report)!=96:raise ValueError('Mirror result length differs')
        v=struct.unpack('<8sII4q2Q32s',report)
        if v[:3]!=(b'A7CRM001',1,0) or any(v[i] for i in (3,4,6)) or v[5]<=0 or v[7] not in m['source_sizes'] or not v[8]:
            raise ValueError('Mirror result reports an incomplete read')
        data=camera.read_temp('a7cr.six.boundary.data')
        allowed=(package.resources[RESOURCE],package.named_resources[RESOURCE])
        if len(data)!=v[7]+1 or data[-1:]!=b'\xa7' or data[:-1] not in allowed or bytes.fromhex(sha(data[:-1]))!=v[9]:
            raise ValueError('Independent full resource mirror readback differs')
        evidence=folder/('boundary-mirror-result-'+uuid.uuid4().hex[:16]+'.private.bin')
        store_private(evidence,report)
    except BaseException:
        camera.healthy=False;raise
    expected['a7cr.six.boundary.result']=report;expected['a7cr.six.boundary.data']=data
    record('readonly_resource_mirror_returned',resource=RESOURCE,bytes=v[7],sha256=sha(data[:-1]),pid=v[5],evidence=evidence.name)
    for name in ('libJit.so','a7cr.six.boundary.data','a7cr.six.boundary.result','a7cr.six.boundary.so'):
        camera.remove_temp(name,expected)
    return data[:-1]
