"""Exact loader comparison and bounded actual single-slot CP bootstrap replay.

This is not a camera boot, MMU/ISP simulation, or recovery guarantee.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

import sys as _path_sys
_path_sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.project_paths import runtime_root
ROOT = runtime_root(Path(__file__).resolve().parents[1])
sys.path.insert(0,str(ROOT/'offline'))
from audit_lut_bootstrap import replay
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN


def check(candidate):
    candidate=Path(candidate).resolve()
    manifest=json.loads((candidate/'candidate.private.json').read_text())
    sha=lambda b:hashlib.sha256(b).hexdigest()
    cp=(candidate/'candidate-CP.private.bin').read_bytes()
    if sha(cp)!=manifest['programs']['CP']['candidate_sha256'] or manifest['selected_mask']!=1:
        raise ValueError('Single-slot candidate identity differs')
    files=[]
    for name in ('loader_spi.bin','mini_ldr.bin','nor-loader_nor.bin'):
        a=(ROOT/'private/components/ILCE-7CR_2.01/lut-references'/name).read_bytes()
        b=(ROOT/'private/components/ILCE-7CM2_2.01/lut-references'/name).read_bytes()
        if a!=b:raise ValueError('Loader comparison variant differs: '+name)
        files.append({'name':name,'bytes':len(a),'sha256':sha(a)})
    stock=(ROOT/'private/components/ILCE-7CR_2.01/cpapp-b.bin').read_bytes()
    donor=(ROOT/'private/components/ILCE-7CM2_2.01/cpapp-b.bin').read_bytes()
    if stock[:0x1000]!=donor[:0x1000] or cp[:0x8000]!=stock[:0x8000]:
        raise ValueError('Bootstrap/prefix source changed')
    nor=(ROOT/'private/components/ILCE-7CR_2.01/lut-references/nor-loader_nor.bin').read_bytes()
    # Literal constants and direct branches of the exact common NOR reader
    # must match the source previously relied on by the reviewed six-slot port.
    decoder=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
    rows=[{'address':i.address,'mnemonic':i.mnemonic,'operands':i.op_str}
          for i in decoder.disasm(nor[0xf9c8:0xfa08],0xf9c8)]
    if not any(i['address']==0xf9e8 and i['mnemonic']=='mov' and i['operands']=='w2, #0x500000' for i in rows):
        raise ValueError('NOR 5MiB preload instruction is not established')
    result=replay(cp)
    if not result['ok']:raise ValueError('Single-slot candidate bootstrap overwrote table storage')
    out={'schema':'a7cr-single-slot-loading-proof/1','passed':True,'camera_accessed':False,
         'candidate_cp_sha256':sha(cp),'exact_common_loaders':files,
         'cp_bootstrap_prefix_matches_stock_and_donor':True,'nor_preload_instructions':rows,
         'proposed_table_file_range':[0x8000,0x8000+7322],
         'bootstrap_replay':result,'hardware_mmu_cache_isp_or_power_loss_verified':False}
    (candidate/'loading-proof.private.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'passed':True,'exact_common_loaders':3,'instructions':result['instructions'],
                      'table_bytes_preserved':result['table_bytes_preserved'],'camera_accessed':False}))
    return out


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate',type=Path,required=True)
    check(p.parse_args().candidate)
