"""Exact-source, offline A7CR single-slot candidate; never accesses a camera.

The reviewed A7CR full7-v4 port supplies the native code. Its six-table
storage ABI is retained, but only one AP selector is enabled and only that
slot's label record is changed. Unreachable banks contain zero corrections.
This output is deliberately not a device-installation package.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

import sys as _path_sys
_path_sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.project_paths import runtime_root
ROOT = runtime_root(Path(__file__).resolve().parents[1])
INPUT = ROOT / 'private/install/fl23/payload'
UPSTREAM = ROOT / 'research/repos/a7c2-fl23-research'
ASSETS = UPSTREAM / 'src/looks/assets/runtime-v1.json'
COMPARISON = ROOT / 'private/components/ILCE-7CM2_2.01'
EXPECTED = {
    'AP': '4ff7051bfca944b02ce150f911357d5d0173bbf2bfad01a08c9dea13a0dac019',
    'CP': '7c6a4baca721232aefe945ebd080cda5665c6c9488d61fa81849156b9302c446',
}
AP_ENTRY, AP_END, AP_GETTER, AP_MAP = 0x3528cd8, 0x3528d5c, 0x1b5ce5c, 0x4c7d4cc
CP_BASE, CP_HELPER, CP_CHECKER = 0x108000, 0xc2f490, 0xc2ff10
TABLE_BYTES = 1215
ASSET_CANONICAL_SHA = '2dd101144d7dd7a30e210978fe1083c0f5551826ef4dd2a992f8506ddbd2ca65'
NATIVE_MAP = bytes([0, 3, 2, 1, 16, 15, 17, 18, 5, 13, 19, 20])


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def selected_slot(slot, name):
    if type(slot) is not int or slot not in range(1, 7):
        raise ValueError('Select exactly one custom slot 1..6')
    if not isinstance(name, str) or not name.strip() or len(name.encode('utf-8')) > 63 or any(ord(c) < 32 for c in name):
        raise ValueError('Name requires 1..63 UTF-8 bytes without control characters')
    return {'slot': slot, 'mask': 1 << (slot - 1), 'selector': slot + 9,
            'marker': slot + 248, 'label_id': 0x0200ab2b + slot,
            'name': name, 'required_base': 'ST', 'preserve_slots': [i for i in range(1, 7) if i != slot]}


def dependency_report():
    required = {'source_AP': INPUT / 'candidate-AP.private.bin', 'source_CP': INPUT / 'candidate-CP.private.bin',
                'comparison_AP': COMPARISON / 'appFw.so', 'comparison_CP': COMPARISON / 'cpapp-b.bin',
                'pinned_runtime_assets': ASSETS}
    missing = [{'requirement': key, 'path': str(path)} for key, path in required.items() if not path.is_file()]
    for module in ('keystone', 'unicorn'):
        if importlib.util.find_spec(module) is None:
            missing.append({'requirement': module, 'path': None})
    if not any(row['requirement'] == 'keystone' for row in missing):
        try:
            from keystone import Ks, KS_ARCH_ARM, KS_ARCH_ARM64, KS_MODE_THUMB, KS_MODE_LITTLE_ENDIAN
            for arch, mode in ((KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN), (KS_ARCH_ARM, KS_MODE_THUMB)):
                encoded, _ = Ks(arch, mode).asm('nop', addr=0x1000)
                if not encoded: raise ValueError('Assembler returned no instruction bytes')
        except Exception as error:
            missing.append({'requirement': 'functional_arm64_and_thumb_assembler', 'path': None, 'error': str(error)})
    return {'camera_accessed': False, 'ready_to_build': not missing, 'missing': missing,
            'device_install_eligible': False}


class Patches:
    """Checked, bounded, non-overlapping forward/reverse windows."""
    def __init__(self, originals):
        if set(originals) != {'AP', 'CP'} or any(type(v) is not bytes for v in originals.values()):
            raise ValueError('Supply immutable AP/CP source bytes')
        self.originals = dict(originals)
        self.targets = {key: bytearray(value) for key, value in originals.items()}
        self.windows = {key: [] for key in originals}

    def put(self, kind, offset, before, after, purpose):
        if kind not in self.targets or type(offset) is not int or offset < 0 or not before or len(before) != len(after):
            raise ValueError('Invalid candidate window')
        end = offset + len(before)
        if end > len(self.targets[kind]) or self.originals[kind][offset:end] != before:
            raise ValueError('Exact candidate window source differs')
        if any(offset < w['offset'] + w['bytes'] and end > w['offset'] for w in self.windows[kind]):
            raise ValueError('Overlapping candidate window')
        self.targets[kind][offset:end] = after
        self.windows[kind].append({'offset': offset, 'bytes': len(before), 'before_hex': before.hex(),
                                  'after_hex': after.hex(), 'purpose': purpose})

    def finish(self):
        results = {key: bytes(value) for key, value in self.targets.items()}
        for kind, raw in results.items():
            forward, reverse = bytearray(self.originals[kind]), bytearray(raw)
            for w in self.windows[kind]:
                lo, hi = w['offset'], w['offset'] + w['bytes']
                forward[lo:hi] = bytes.fromhex(w['after_hex'])
                reverse[lo:hi] = bytes.fromhex(w['before_hex'])
            if bytes(forward) != raw or bytes(reverse) != self.originals[kind]:
                raise ValueError('Complete forward/inverse reconstruction differs')
            self.windows[kind].sort(key=lambda row: row['offset'])
        return results


def validate_sources(originals, comparison, assets):
    if sha(json.dumps(assets, sort_keys=True, separators=(',', ':')).encode()) != ASSET_CANONICAL_SHA:
        raise ValueError('Pinned runtime reference metadata changed')
    if set(originals) != {'AP', 'CP'} or any(sha(raw) != EXPECTED[kind] for kind, raw in originals.items()):
        raise ValueError('Exact reviewed A7CR FL23 source programs required')
    if set(comparison) != {'AP', 'CP'}:
        raise ValueError('Both exact official A7C II comparison programs are required')
    for kind, raw in comparison.items():
        stock = [row for row in assets[kind.lower() + '_sources'] if row['kind'] == 'stock']
        if len(stock) != 1 or sha(raw) != stock[0]['sha256']:
            raise ValueError('Pinned official A7C II comparison source differs: ' + kind)


def build_candidate(originals, comparison, table, assets, *, slot=1, name='Classic Chrome'):
    """Return immutable programs plus a non-installable review manifest.

    Source bytes are injectable for callers, but the identity check is never
    optional: all four program hashes must match the reviewed exact sources.
    """
    plan = selected_slot(slot, name)
    validate_sources(originals, comparison, assets)
    sys.path.insert(0, str(UPSTREAM / 'src/looks'))
    from looktool import native, six
    if type(table) is not bytes:
        raise ValueError('Supply an immutable native table')
    native.decode(table)
    if len(table) != TABLE_BYTES:
        raise ValueError('Expected one 1215-byte native correction table')
    # No import of device modules, and no dependency acquisition here.
    from build_lut_candidate import ap_code, cp_code, assembler, KS_ARCH_ARM
    source_ap, source_cp = originals['AP'], originals['CP']
    cii_ap = comparison['AP']
    changes = Patches(originals)
    code, branch = ap_code(plan['mask'])
    getter = cii_ap[0x1b5cd78:0x1b5cd98]
    if len(getter) != 32 or source_ap.count(getter) != 1 or source_ap.find(getter) != AP_GETTER - 4:
        raise ValueError('A7CR title getter is not uniquely matched to pinned comparison')
    changes.put('AP', AP_ENTRY, source_ap[AP_ENTRY:AP_END], code, 'Single-mask ST converter and bounded title helper')
    changes.put('AP', AP_GETTER, bytes.fromhex('fd030091'), branch, 'Preserved-frame title getter branch')
    changes.put('AP', AP_MAP, bytes.fromhex('1200020406080a0c0e100000'), NATIVE_MAP, 'Native map including preserved FL2/FL3')
    label_at = 0x59896f0 + (slot - 1) * 0xb8
    if source_ap[label_at - 32:label_at + 36] != cii_ap[label_at - 32:label_at + 36]:
        raise ValueError('Selected native menu label row differs from pinned comparison')
    changes.put('AP', label_at, struct.pack('<I', 0x0200a302), struct.pack('<I', plan['label_id']), 'Only the selected custom-slot label')
    thumb = assembler(KS_ARCH_ARM)
    fl23 = [row for row in assets['cp_sources'] if row['kind'] == 'fl23']
    if len(fl23) != 1:
        raise ValueError('Pinned FL23 CP reference is not unique')
    original = bytes.fromhex(next(w for w in fl23[0]['windows'] if w['offset'] == 0x1354b8)['before'])
    if source_cp.count(original) != 1 or source_cp.find(original) != 0x1354d8:
        raise ValueError('A7CR native CP controller is not uniquely matched')
    block = bytearray(original)
    block[:16] = thumb(f'bl 0x{CP_HELPER:x}', 0x23d4d8) + bytes.fromhex('00bf') * 6
    block[0x1a:0x1c] = thumb('cbz r4,0x23d504', 0x23d4f2)
    block[0x2a:0x2c] = thumb('b 0x23d504', 0x23d502)
    block[0x2c:0x30] = thumb(f'b.w 0x{CP_HELPER+0x90:x}', 0x23d504)
    changes.put('CP', 0x1354d8, original, bytes(block), 'Native full7 dispatch and repaired incoming branch boundary')
    changes.put('CP', 0x13555a, thumb('movw r0,#0x1760', 0x23d55a), thumb('b.w 0xc2f50e', 0x23d55a), 'Reviewed v4 cached-preview upload retry')
    changes.put('CP', 0x1358e8, thumb('movs r5,#0;b 0x23dbb8', 0x23d8e8), thumb('b.w 0xc2ff70', 0x23d8e8), 'Validated custom-marker switch bridge')
    for at in (0x32338a, 0x3234b0):
        changes.put('CP', at, thumb('bl 0x240852', at + CP_BASE), thumb(f'bl 0x{CP_HELPER+0x70:x}', at + CP_BASE), 'Native gamma normalization preserving FL23 routes')
    helper, checker = cp_code()
    changes.put('CP', CP_HELPER - CP_BASE, bytes(len(helper)), helper, 'Reviewed guarded full7 helper')
    changes.put('CP', CP_CHECKER - CP_BASE, bytes(len(checker)), checker, 'Per-use FNV validation and native switch bridge')
    tables = [bytes(TABLE_BYTES) for _ in range(6)]
    tables[slot - 1] = table
    prefix = six.prefix(tables)
    changes.put('CP', 0x8000, bytes(len(prefix)), prefix, 'Six-table ABI: one selected table, five zero-correction banks')
    if struct.unpack_from('<3I', source_cp, 0x20124) != (0, 0xb072e8, 0x128000):
        raise ValueError('Unknown A7CR text descriptor')
    changes.put('CP', 0x20128, struct.pack('<I', 0xb072e8), struct.pack('<I', 0xb07fb0), 'Load reviewed helper tail without moving data/BSS')
    result = changes.finish()
    if six.read_tables(result['CP']) != tables:
        raise ValueError('Stored native table/checksum readback differs')
    for other in plan['preserve_slots']:
        at = 0x59896f0 + (other - 1) * 0xb8
        if result['AP'][at - 32:at + 36] != source_ap[at - 32:at + 36]:
            raise ValueError('An unselected slot label record changed')
    manifest = {
        'schema': 'a7cr-single-slot-candidate/1', 'model': 'ILCE-7CR', 'version': '2.01',
        'camera_accessed': False, 'device_install_eligible': False, 'installable': False,
        'selection': plan, 'selected_mask': plan['mask'], 'names': {str(slot): name},
        'native_grid': [5, 9, 9], 'native_signed_bits': 7,
        'selected_table_sha256': sha(table), 'unused_banks': 'zero corrections; AP emits no custom marker for unselected slots',
        'programs': {kind: {'bytes': len(result[kind]), 'source_sha256': sha(originals[kind]),
                            'candidate_sha256': sha(result[kind]), 'windows': changes.windows[kind]} for kind in result},
        'comparison_source_sha256': {kind: sha(raw) for kind, raw in comparison.items()},
        'inverse_full_files_exact': True, 'unselected_slot_label_records_preserved': True,
        'native_instruction_tests_passed': False, 'placement_audit_passed': False,
        'remaining': ['Fresh body-bound resources/settings checkpoint', 'One-slot resource transaction and native ST synchronization',
                      'Program placement/loader audit', 'Native instruction/failure simulation',
                      'Reviewed restore-to-current-FL23 flow', 'Cold-load, preview and new-photo validation'],
    }
    return result, manifest


def verify_native_paths(originals, candidate, manifest):
    """Execute actual selected-mask AP and CP paths under a synthetic CPU.

    This does not emulate an ISP, RTOS, USB, filesystem or power loss. It
    validates dispatch/frame behavior, the selected upload and legacy paths.
    """
    for kind in ('AP', 'CP'):
        if sha(originals[kind]) != manifest['programs'][kind]['source_sha256'] or sha(candidate[kind]) != manifest['programs'][kind]['candidate_sha256']:
            raise ValueError('Native test program identity differs')
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
    from unicorn.arm64_const import (UC_ARM64_REG_W0, UC_ARM64_REG_W1, UC_ARM64_REG_X0,
        UC_ARM64_REG_X2, UC_ARM64_REG_X29, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC)
    from check_lut_candidate import harness, gamma_tests
    plan = manifest['selection']
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for at, size in ((AP_ENTRY & ~4095, 0x2000), (AP_GETTER & ~4095, 0x2000), (AP_MAP & ~4095, 4096), (0x30000000, 0x3000)):
        u.mem_map(at, size)
    for at, n in ((AP_ENTRY, AP_END - AP_ENTRY), (AP_GETTER - 4, 40), (AP_MAP, 12)):
        u.mem_write(at, candidate['AP'][at:at + n])
    halt, stack, count = 0x30002000, 0x30001000, 0
    for selector in range(18):
        for base in list(range(12)) + [255]:
            for reg, value in ((UC_ARM64_REG_W0, selector), (UC_ARM64_REG_W1, base), (UC_ARM64_REG_X2, 0x30000000),
                               (UC_ARM64_REG_X30, halt), (UC_ARM64_REG_SP, stack)):
                u.reg_write(reg, value)
            u.mem_write(0x30000000, b'\xa5')
            u.emu_start(AP_ENTRY, AP_END if base > 11 and selector != 16 else halt, count=50)
            expected = (255 if selector == 16 else plan['marker'] if base == 0 and selector == plan['selector']
                        else NATIVE_MAP[base] if base <= 11 else 165)
            expected_pc = AP_END if expected == 165 else halt
            if u.mem_read(0x30000000, 1)[0] != expected or u.reg_read(UC_ARM64_REG_PC) != expected_pc or u.reg_read(UC_ARM64_REG_SP) != stack:
                raise ValueError(f'Single-slot AP dispatch differs: selector={selector} base={base}')
            count += 1
    for identity in (0, 0x7f7, *range(0x7f8, 0x7fe), 0x7fe, 0xffffffff):
        for reg, value in ((UC_ARM64_REG_X0, 0x112233445566), (UC_ARM64_REG_W1, identity), (UC_ARM64_REG_SP, stack),
                           (UC_ARM64_REG_X29, 0x12345678), (UC_ARM64_REG_X30, halt)):
            u.reg_write(reg, value)
        selected = identity == 0x7f8 + plan['slot'] - 1
        u.emu_start(AP_GETTER - 4, halt if selected else AP_GETTER + 4, count=40)
        if selected:
            if (u.reg_read(UC_ARM64_REG_W0) != plan['label_id'] or u.reg_read(UC_ARM64_REG_SP) != stack
                    or u.reg_read(UC_ARM64_REG_X29) != 0x12345678 or u.reg_read(UC_ARM64_REG_PC) != halt):
                raise ValueError('Selected title did not preserve the native frame ABI')
        elif (u.reg_read(UC_ARM64_REG_X0) != 0x112233445566 or u.reg_read(UC_ARM64_REG_W1) != identity
                or u.reg_read(UC_ARM64_REG_SP) != stack - 16 or u.reg_read(UC_ARM64_REG_X29) != stack - 16
                or bytes(u.mem_read(stack - 16, 16)) != struct.pack('<QQ', 0x12345678, halt)):
            raise ValueError('Unselected native title continuation changed')
        count += 1
    schedule = harness()['schedule']
    controller_cases = 0
    marker = plan['marker']
    for consumer in range(4):
        for root3 in (0, 1):
            rows = [(marker, consumer, False), (marker, consumer, True), (marker, consumer, True)]
            states, counters = schedule(candidate['CP'], rows, root3=root3)
            if not all(row['hardware_bytes_match'] for row in states[1:]) or counters['builds'] != 1:
                raise ValueError('Single-slot native cached-preview upload differs')
            controller_cases += 1
    native = [(mode, 0, True) for mode in (0, 1, 2, 3, 5, 13, 15, 16, 17, 18, 19, 20, 255)]
    for flag in (0, 1):
        for direct in (0, 1):
            for domain in (0, 8, 11):
                for root3 in (0, 1):
                    options = dict(flag=flag, direct=direct, domain=domain, root3=root3)
                    if schedule(originals['CP'], native, **options) != schedule(candidate['CP'], native, **options):
                        raise ValueError('An original native/FL23 controller path changed')
                    controller_cases += 1
    bad = bytearray(candidate['CP']); bad[0x8008 + (plan['slot'] - 1) * 4] ^= 1
    states, _ = schedule(bytes(bad), [(marker, 0, True)])
    if states[0]['enabled']:
        raise ValueError('Corrupted selected table checksum was accepted')
    controller_cases += 1
    return {'camera_accessed': False, 'ap_instruction_cases': count, 'cp_controller_cases': controller_cases,
            'gamma_cases': gamma_tests(originals['CP'], candidate['CP']), 'passed': True,
            'limitations': 'Synthetic CPU and MMIO; not hardware/ISP timing, filesystem or physical cold-load proof'}


def write_candidate(directory, programs, manifest):
    if (set(programs) != {'AP', 'CP'} or manifest.get('schema') != 'a7cr-single-slot-candidate/1'
            or manifest.get('installable') is not False or manifest.get('device_install_eligible') is not False
            or manifest.get('camera_accessed') is not False):
        raise ValueError('Only a non-installable offline candidate may be written')
    for kind, raw in programs.items():
        spec = manifest['programs'][kind]
        if type(raw) is not bytes or len(raw) != spec['bytes'] or sha(raw) != spec['candidate_sha256'] or spec['source_sha256'] != EXPECTED[kind]:
            raise ValueError('Candidate program identity differs from the review manifest')
    directory = Path(directory).resolve()
    # Candidate data cannot overwrite the reviewed input or a legacy install task.
    protected = (INPUT, ROOT / 'private/install', ROOT / 'private/lut-install')
    if any(directory == p or p in directory.parents or directory in p.parents for p in protected):
        raise ValueError('Use a new output directory separate from source payload')
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    for kind, raw in programs.items():
        path = directory / f'candidate-{kind}.private.bin'
        path.write_bytes(raw); path.chmod(0o600)
    path = directory / 'candidate.private.json'
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n'); path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--requirements', action='store_true', help='Report local prerequisites; no camera access')
    parser.add_argument('--verify-native', action='store_true', help='Run actual AP/CP instruction paths in synthetic CPU; no camera access')
    parser.add_argument('--table', type=Path)
    parser.add_argument('--slot', type=int, default=1)
    parser.add_argument('--name', default='Classic Chrome')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    required = dependency_report()
    if args.requirements:
        print(json.dumps(required, indent=2));return
    if args.table is None or args.output is None:
        parser.error('--table and --output are required')
    if not required['ready_to_build']:
        print(json.dumps(required, indent=2));raise SystemExit(2)
    original = {k: (INPUT / f'candidate-{k}.private.bin').read_bytes() for k in EXPECTED}
    comparison = {'AP': (COMPARISON / 'appFw.so').read_bytes(), 'CP': (COMPARISON / 'cpapp-b.bin').read_bytes()}
    result, report = build_candidate(original, comparison, args.table.read_bytes(), json.loads(ASSETS.read_text()), slot=args.slot, name=args.name)
    if args.verify_native:
        report['native_instruction_tests'] = verify_native_paths(original, result, report)
        report['native_instruction_tests_passed'] = True
    write_candidate(args.output, result, report)
    print(json.dumps({'output': str(args.output.resolve()), 'selected_mask': report['selected_mask'],
                      'candidate_only': True, 'device_install_eligible': False, 'inverse_full_files_exact': True}, indent=2))


if __name__ == '__main__':
    main()
