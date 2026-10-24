"""Offline preservation, source admission, inverse and real-instruction checks."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import single_slot_candidate as mod


class WindowTests(unittest.TestCase):
    def test_exact_forward_and_inverse_preserve_bytes_outside_windows(self):
        originals = {'AP': bytes(range(100)), 'CP': bytes(range(80))}
        p = mod.Patches(originals)
        p.put('AP', 4, originals['AP'][4:8], b'look', 'synthetic AP window')
        p.put('CP', 72, originals['CP'][72:80], b'12345678', 'synthetic CP tail')
        result = p.finish()
        self.assertEqual(result['AP'][:4] + result['AP'][8:], originals['AP'][:4] + originals['AP'][8:])
        self.assertEqual(result['CP'][:72], originals['CP'][:72])
        for kind in originals:
            inverse = bytearray(result[kind])
            for w in p.windows[kind]:
                inverse[w['offset']:w['offset'] + w['bytes']] = bytes.fromhex(w['before_hex'])
            self.assertEqual(bytes(inverse), originals[kind])

    def test_overlap_wrong_source_and_resize_stop_before_second_change(self):
        p = mod.Patches({'AP': b'abcdefgh', 'CP': b'01234567'})
        p.put('AP', 2, b'cd', b'XY', 'first')
        for args in [('AP', 3, b'de', b'zz', 'overlap'), ('CP', 1, b'XX', b'YY', 'wrong source'),
                     ('CP', 7, b'7x', b'YY', 'truncated source'), ('CP', 2, b'23', b'x', 'resize')]:
            with self.assertRaises(ValueError):p.put(*args)
        result = p.finish()
        self.assertEqual(result, {'AP': b'abXYefgh', 'CP': b'01234567'})

    def test_out_of_window_mutation_fails_complete_reconstruction(self):
        p = mod.Patches({'AP': b'abcdefgh', 'CP': b'01234567'})
        p.put('AP', 1, b'b', b'X', 'declared')
        p.targets['AP'][6] = 0
        with self.assertRaises(ValueError):p.finish()

    def test_single_selection_never_enables_or_renames_other_slots(self):
        for slot in range(1, 7):
            p = mod.selected_slot(slot, 'Classic Chrome')
            self.assertEqual(p['mask'].bit_count(), 1)
            self.assertEqual(p['mask'], 1 << (slot - 1))
            self.assertEqual(p['preserve_slots'], [i for i in range(1, 7) if i != slot])
        for slot in (0, 7, True, '1'):
            with self.assertRaises(ValueError):mod.selected_slot(slot, 'Classic Chrome')
        for name in ('', ' ', 'CC\n', 'A' * 64):
            with self.assertRaises(ValueError):mod.selected_slot(1, name)

    def test_cannot_admit_unknown_sources_or_modified_reference_metadata(self):
        assets = json.loads(mod.ASSETS.read_text())
        with self.assertRaisesRegex(ValueError, 'A7CR FL23'):
            mod.validate_sources({'AP': b'unknown', 'CP': b'unknown'}, {}, assets)
        assets['cp_sources'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'reference metadata'):
            mod.validate_sources({'AP': b'unknown', 'CP': b'unknown'}, {}, assets)

    def test_cannot_write_over_source_or_install_tasks(self):
        programs = {'AP': b'synthetic AP', 'CP': b'synthetic CP'}
        manifest = {'schema': 'a7cr-single-slot-candidate/1', 'camera_accessed': False, 'installable': False,
                    'device_install_eligible': False, 'programs': {kind: {'bytes': len(raw), 'candidate_sha256': mod.sha(raw),
                    'source_sha256': mod.EXPECTED[kind]} for kind, raw in programs.items()}}
        for path in (mod.INPUT, mod.INPUT/'nested', mod.INPUT.parent, mod.ROOT/'private/install/new-single-slot', mod.ROOT/'private/lut-install/new'):
            with self.assertRaisesRegex(ValueError, 'separate from source'):
                mod.write_candidate(path, programs, manifest)

    def test_writer_rejects_installable_or_changed_program_manifest(self):
        programs = {'AP': b'synthetic AP', 'CP': b'synthetic CP'}
        manifest = {'schema': 'a7cr-single-slot-candidate/1', 'camera_accessed': False, 'installable': False,
                    'device_install_eligible': False, 'programs': {kind: {'bytes': len(raw), 'candidate_sha256': mod.sha(raw),
                    'source_sha256': mod.EXPECTED[kind]} for kind, raw in programs.items()}}
        with tempfile.TemporaryDirectory() as folder:
            for key in ('camera_accessed', 'installable', 'device_install_eligible'):
                bad = dict(manifest);bad[key] = True
                with self.assertRaises(ValueError):mod.write_candidate(Path(folder)/key, programs, bad)
            bad = copy.deepcopy(manifest);bad['programs']['CP']['candidate_sha256'] = '0'*64
            with self.assertRaises(ValueError):mod.write_candidate(Path(folder)/'changed', programs, bad)
            self.assertEqual(list(Path(folder).iterdir()), [])


def fixture_ready():
    return mod.dependency_report()['ready_to_build'] and (mod.ROOT/'private/single-slot-input/fit/slot.raw-s8.private.bin').is_file()


@unittest.skipUnless(fixture_ready(), 'Exact private program/comparison/Classic Chrome fixtures and assembler must be present')
class ActualSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.originals = {k: (mod.INPUT/f'candidate-{k}.private.bin').read_bytes() for k in ('AP', 'CP')}
        cls.comparison = {'AP': (mod.COMPARISON/'appFw.so').read_bytes(), 'CP': (mod.COMPARISON/'cpapp-b.bin').read_bytes()}
        cls.assets = json.loads(mod.ASSETS.read_text())
        cls.table = (mod.ROOT/'private/single-slot-input/fit/slot.raw-s8.private.bin').read_bytes()
        cls.programs, cls.manifest = mod.build_candidate(cls.originals, cls.comparison, cls.table, cls.assets)

    def test_single_slot_actual_patch_scope_and_full_inverse(self):
        self.assertEqual(self.manifest['selected_mask'], 1)
        self.assertEqual(self.manifest['names'], {'1': 'Classic Chrome'})
        self.assertFalse(self.manifest['device_install_eligible'])
        labels = [w for w in self.manifest['programs']['AP']['windows'] if 'label' in w['purpose']]
        self.assertEqual(len(labels), 1)
        self.assertEqual(labels[0]['offset'], 0x59896f0)
        for other in range(2, 7):
            at = 0x59896f0 + (other - 1)*0xb8
            self.assertEqual(self.programs['AP'][at-32:at+36], self.originals['AP'][at-32:at+36])
        for kind, raw in self.programs.items():
            inverse = bytearray(raw)
            for w in self.manifest['programs'][kind]['windows']:
                lo = w['offset'];inverse[lo:lo+w['bytes']] = bytes.fromhex(w['before_hex'])
            self.assertEqual(bytes(inverse), self.originals[kind])

    def test_unused_table_banks_are_neutral_and_integrity_checked(self):
        from looktool.six import read_tables
        tables = read_tables(self.programs['CP'])
        self.assertEqual(tables[0], self.table)
        self.assertEqual(tables[1:], [bytes(mod.TABLE_BYTES)]*5)
        bad = bytearray(self.programs['CP']);bad[0x8020 + mod.TABLE_BYTES + 10] ^= 1
        with self.assertRaises(ValueError):read_tables(bytes(bad))

    def test_native_actual_single_slot_and_legacy_paths(self):
        report = mod.verify_native_paths(self.originals, self.programs, self.manifest)
        self.assertTrue(report['passed'])
        self.assertEqual(report['ap_instruction_cases'], 244)
        self.assertEqual(report['cp_controller_cases'], 33)
        self.assertEqual(report['gamma_cases'], 512)

    def test_full_six_mask_mutant_is_detected_by_actual_instructions(self):
        from build_lut_candidate import ap_code
        programs = dict(self.programs);ap = bytearray(programs['AP'])
        ap[mod.AP_ENTRY:mod.AP_END] = ap_code(63)[0]
        programs['AP'] = bytes(ap)
        manifest = copy.deepcopy(self.manifest)
        manifest['programs']['AP']['candidate_sha256'] = mod.sha(programs['AP'])
        with self.assertRaisesRegex(ValueError, 'AP dispatch'):
            mod.verify_native_paths(self.originals, programs, manifest)

    def test_exact_sources_reject_single_byte_and_truncated_donors(self):
        bad = dict(self.originals);bad['AP'] = bytes([bad['AP'][0] ^ 1]) + bad['AP'][1:]
        with self.assertRaises(ValueError):mod.build_candidate(bad, self.comparison, self.table, self.assets)
        donor = dict(self.comparison);donor['CP'] = donor['CP'][:-1]
        with self.assertRaises(ValueError):mod.build_candidate(self.originals, donor, self.table, self.assets)

    def test_writes_new_private_output_only(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)/'candidate'
            mod.write_candidate(output, self.programs, self.manifest)
            self.assertEqual((output/'candidate-CP.private.bin').read_bytes(), self.programs['CP'])
            self.assertEqual((output/'candidate.private.json').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):mod.write_candidate(output, self.programs, self.manifest)


if __name__ == '__main__':
    unittest.main()
