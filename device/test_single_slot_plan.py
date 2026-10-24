"""Offline transaction scenarios; no camera imports or transport simulation."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import unittest

import single_slot_plan as m


class SingleSlotPlanTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)
        self.body, self.worker = m.digest(b"body fixture"), m.digest(b"native worker fixture")
        self.programs = {
            "AP": m.ProgramDelta("AP", b"original-AP-image", b"original-AP-IMAGE", (m.Window(12, b"image", b"IMAGE"),)),
            "CP": m.ProgramDelta("CP", b"original-CP-image", b"original-CP-IMAGE", (m.Window(12, b"image", b"IMAGE"),)),
        }
        original = {k:m.digest(v.original) for k,v in self.programs.items()}
        self.target = {k:m.digest(v.target) for k,v in self.programs.items()}
        self.resources = tuple(m.Resource(f"string_language{i}_horizontal.uxc",
            m.digest(f"original {i}".encode()), m.digest(f"renamed {i}".encode())) for i in range(68))
        self.fields = (m.Field(m.BASE_KEY, b"\x09", m.ST),) + tuple(
            m.Field(key, (i+1).to_bytes(4, "little"), b"\0"*4) for i,key in enumerate(m.SLOT_KEYS[1:]))
        # Synthetic small full-file fixtures exercise the pure planner without
        # shipping 118 MiB of private camera firmware. Production constants are
        # unchanged outside construction of this one test checkpoint.
        with patch.dict(m.FL23_SHA256, original):
            self.checkpoint = m.Checkpoint(self.body, "fresh-checkpoint", self.now-timedelta(seconds=60),
                original, self.resources, self.fields, 2, True, True, True)

    def observation(self, *, programs=None, renamed=False, staged=True, edits=None, base=0, selection=0):
        values={f.key:(f.target if staged else f.before) for f in self.fields}
        values.update(edits or {})
        values[m.BASE_KEY]=bytes([base])
        return m.Observation(self.body,"service-session-1",self.now-timedelta(seconds=1),
            programs or self.checkpoint.program_sha256,
            {r.name:(r.target_sha256 if renamed else r.original_sha256) for r in self.resources},
            dict(values),dict(values),{1:base,2:9,3:2,4:4,5:10,6:11},selection)

    def sync(self,current, *, prior_base=0, prior_selection=None):
        before=dict(current.runtime_bases);before[1]=prior_base
        return m.NativeSync(self.body,current.session_id,current.captured_at,self.worker,
            True,True,(1,),True,before,dict(current.runtime_bases),bytes([prior_base]),bytes([prior_base]),
            current.current_selection if prior_selection is None else prior_selection,current.current_selection)

    def install(self,current,sync=None,**kw):
        return m.install_plan(self.checkpoint,self.programs,current,sync or self.sync(current),
            reviewed_worker_sha256=self.worker,battery_percent=90,now=self.now,**kw)

    def recover(self,current,sync=None,**kw):
        return m.recovery_plan(self.checkpoint,self.programs,current,sync or self.sync(current),
            reviewed_worker_sha256=self.worker,battery_percent=90,now=self.now,**kw)

    def test_first_install_requires_st_before_cp_and_activates_ap_last(self):
        plan=self.install(self.observation())
        actions=[(s.action,s.scope) for s in plan.operations]
        self.assertEqual(actions[0],("native_st_already_verified","slot:1"))
        self.assertLess(actions.index(("write_and_full_readback","CP")),actions.index(("write_and_full_readback","AP")))
        self.assertEqual(sum(s.scope.startswith("resource:") for s in plan.operations),68)
        self.assertFalse(plan.executable)

    def test_staging_changes_only_nine_slot1_fields_and_requires_native_readback(self):
        current=self.observation(staged=False,base=9)
        plan=m.staging_plan(self.checkpoint,current,now=self.now)
        keys={int(s.scope[8:],16) for s in plan.operations if s.scope.startswith("setting:")}
        self.assertEqual(keys,set(m.SLOT_KEYS))
        self.assertIn("native_menu_sync_and_independent_readback",[s.action for s in plan.operations])
        self.assertFalse(any(s.scope in ("AP","CP") for s in plan.operations))

    def test_saved_and_backup_ram_st_do_not_prove_runtime_st(self):
        current=self.observation()
        current=replace(current,runtime_bases={**current.runtime_bases,1:8})
        with self.assertRaises(m.ReviewRequired):self.install(current)

    def test_native_receipt_from_another_session_is_rejected(self):
        current=self.observation()
        with self.assertRaises(m.ReviewRequired):self.install(current,replace(self.sync(current),session_id="old-session"))

    def test_native_setter_changing_another_slot_is_rejected(self):
        current=self.observation();sync=self.sync(current)
        sync=replace(sync,before_bases={**sync.before_bases,2:8})
        with self.assertRaises(m.ReviewRequired):self.install(current,sync)

    def test_settings_not_staged_block_program_writes(self):
        current=self.observation(edits={m.SLOT_KEYS[3]:b"\x07\0\0\0"})
        with self.assertRaises(m.ReviewRequired):self.install(current)

    def test_known_partial_and_imported_states_are_not_first_install_retries(self):
        for hashes,renamed in (({"AP":self.checkpoint.program_sha256["AP"],"CP":self.target["CP"]},False),
                              (self.target,True)):
            with self.subTest(hashes=hashes),self.assertRaises(m.ReviewRequired):self.install(self.observation(programs=hashes,renamed=renamed))

    def test_complete_readback_classifies_supported_and_partial_stages(self):
        cases=[(self.checkpoint.program_sha256,False,"FL23_ORIGINAL"),
               ({"AP":self.checkpoint.program_sha256["AP"],"CP":self.target["CP"]},False,"CP_ONLY"),
               ({"AP":self.checkpoint.program_sha256["AP"],"CP":self.target["CP"]},True,"CP_AND_NAMES"),
               (self.target,True,"IMPORTED_FILES"),
               ({"AP":self.target["AP"],"CP":self.checkpoint.program_sha256["CP"]},False,"PARTIAL_KNOWN")]
        for hashes,renamed,label in cases:
            with self.subTest(label=label):self.assertEqual(m.classify(self.checkpoint,self.observation(programs=hashes,renamed=renamed),self.target),label)

    def test_unknown_program_or_resource_never_gets_inverse_plan(self):
        current=self.observation(programs={**self.target,"CP":m.digest(b"another CP modification")},renamed=True)
        with self.assertRaises(m.ReviewRequired):self.recover(current)
        current=self.observation(programs=self.target,renamed=True)
        current=replace(current,resource_sha256={**current.resource_sha256,self.resources[1].name:m.digest(b"later unrelated rename")})
        with self.assertRaises(m.ReviewRequired):self.recover(current)

    def test_unresolved_intent_blocks_even_when_fresh_hashes_look_known(self):
        journal=(m.JournalEvent("cp-stage","intent"),)
        current=self.observation(programs=self.target,renamed=True)
        with self.assertRaises(m.ReviewRequired):self.recover(current,journal=journal)
        with self.assertRaises(m.ReviewRequired):self.install(self.observation(),journal=journal)

    def test_verified_receipt_requires_matching_intent(self):
        with self.assertRaises(m.ReviewRequired):m.review_journal([m.JournalEvent("ap-stage","verified")])
        self.assertEqual(m.review_journal([m.JournalEvent("cp-stage","intent"),m.JournalEvent("cp-stage","verified")]),("cp-stage",))

    def test_recovery_deactivates_then_restores_ap_before_cp(self):
        current=self.observation(programs=self.target,renamed=True)
        plan=self.recover(current)
        self.assertEqual(plan.operations[0].action,"native_global_st_already_verified")
        programs=[s.scope for s in plan.operations if s.scope in ("AP","CP")]
        self.assertEqual(programs,["AP","CP"])
        self.assertEqual({s.scope for s in plan.operations if s.scope.startswith("setting:")},
                         {f"setting:{key:08x}" for key in m.SLOT_KEYS[1:]})
        self.assertFalse(plan.physical_recovery_verified)

    def test_recovery_cannot_remove_support_while_imported_slot_is_selected(self):
        current=self.observation(programs=self.target,renamed=True,selection=10)
        with self.assertRaises(m.ReviewRequired):self.recover(current)

    def test_recovery_preserves_later_user_adjustment_and_native_base(self):
        edited_key=m.SLOT_KEYS[2]
        current=self.observation(programs=self.target,renamed=True,edits={edited_key:b"\x09\0\0\0"})
        plan=self.recover(current,self.sync(current,prior_base=3))
        self.assertIn(edited_key,plan.preserve_user_fields)
        self.assertIn(m.BASE_KEY,plan.preserve_user_fields)
        self.assertFalse(any(s.scope==f"setting:{edited_key:08x}" for s in plan.operations))
        base=next(s for s in plan.operations if s.action=="restore_selected_base_via_native_menu")
        self.assertEqual(base.target,b"\x03")
        self.assertFalse(any(s.action=="restore_pre_deactivation_selection_via_native_menu" for s in plan.operations))
        self.assertEqual(plan.operations[-1].action,"owner_choose_supported_selection_after_restore")

    def test_slot_sync_must_not_implicitly_change_current_selection(self):
        current=self.observation(programs=self.target,renamed=True)
        with self.assertRaises(m.ReviewRequired):self.recover(current,self.sync(current,prior_selection=10))

    def test_recovery_restores_original_slot_base_when_import_value_still_owned(self):
        current=self.observation(programs=self.target,renamed=True)
        plan=self.recover(current)
        base=next(s for s in plan.operations if s.action=="restore_selected_base_via_native_menu")
        self.assertEqual(base.target,b"\x09")

    def test_unsaved_later_selected_edit_is_not_overwritten(self):
        current=self.observation(programs=self.target,renamed=True)
        current=replace(current,ram_fields={**current.ram_fields,m.SLOT_KEYS[1]:b"\x07\0\0\0"})
        with self.assertRaises(m.ReviewRequired):self.recover(current)

    def test_recovery_of_cp_only_skips_ap_and_already_original_resources(self):
        current=self.observation(programs={"AP":self.checkpoint.program_sha256["AP"],"CP":self.target["CP"]})
        plan=self.recover(current)
        self.assertEqual([s.scope for s in plan.operations if s.action=="inverse_and_full_readback"],["CP"])

    def test_fresh_identity_all_resources_and_power_are_mandatory(self):
        current=self.observation()
        for bad in (replace(current,body_sha256=m.digest(b"other body")),
                    replace(current,captured_at=self.now-timedelta(minutes=10)),
                    replace(current,resource_sha256=dict(list(current.resource_sha256.items())[:-1]))):
            with self.subTest(bad=bad),self.assertRaises(m.ReviewRequired):self.install(bad)
        with self.assertRaises(m.ReviewRequired):
            m.install_plan(self.checkpoint,self.programs,current,self.sync(current),reviewed_worker_sha256=self.worker,battery_percent=74,now=self.now)

    def test_readback_identity_maps_cannot_be_changed_after_validation(self):
        current=self.observation()
        with self.assertRaises(TypeError):current.program_sha256["AP"]=m.digest(b"different")
        with self.assertRaises(TypeError):self.checkpoint.program_sha256["AP"]=m.digest(b"different")


class DeltaTests(unittest.TestCase):
    def test_exact_inverse_and_reject_unknown_file(self):
        d=m.ProgramDelta("AP",b"abcdefgh",b"abXYefgh",(m.Window(2,b"cd",b"XY"),))
        self.assertEqual(d.restore(b"abXYefgh"),b"abcdefgh")
        with self.assertRaises(m.ReviewRequired):d.restore(b"abXYefg!")

    def test_hidden_changes_and_overlapping_windows_are_rejected(self):
        with self.assertRaises(m.ReviewRequired):m.ProgramDelta("AP",b"abcdefgh",b"abXYefg!",(m.Window(2,b"cd",b"XY"),))
        with self.assertRaises(m.ReviewRequired):m.ProgramDelta("AP",b"abcdefgh",b"abXYefgh",(m.Window(2,b"cd",b"XY"),m.Window(3,b"d",b"Y")))

    def test_other_slot_or_raw_companion_write_is_rejected(self):
        for key in (m.BASE_KEY+2,m.COMPANION_KEY,m.SLOT_KEYS[-1]+2):
            with self.subTest(key=key),self.assertRaises(m.ReviewRequired):m.Field(key,b"\0"*4,b"\0"*4)


if __name__=="__main__":unittest.main()
