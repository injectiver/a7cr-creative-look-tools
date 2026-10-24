"""Pure, fail-closed planning for a first A7CR slot-1 import and its inverse.

This module has no USB/native-worker entry point. A Plan describes reviewed
next operations; it cannot execute them. Recovery targets the *current FL23*
checkpoint, never donor calibration or a generic factory image. Native model
synchronization is evidence separate from Backup RAM/storage readback.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import re
from types import MappingProxyType
from typing import Mapping, Sequence


FL23_SHA256 = {
    "AP": "4ff7051bfca944b02ce150f911357d5d0173bbf2bfad01a08c9dea13a0dac019",
    "CP": "7c6a4baca721232aefe945ebd080cda5665c6c9488d61fa81849156b9302c446",
}
BASE_KEY = 0x02CF0CD0
SLOT_KEYS = (BASE_KEY,) + tuple(0x02CF0CF0 + 0x20 * i for i in range(8))
COMPANION_KEY = BASE_KEY + 1  # Native menu setter owns this; never write it raw.
ST = b"\x00"
RESOURCE_COUNT = 68
MIN_BATTERY = 75
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class ReviewRequired(ValueError):
    """Evidence does not support automatic continuation or inverse writes."""


def digest(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def _hash(value: str) -> None:
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        raise ReviewRequired("A complete SHA256 identity is required")


def _time(value: datetime) -> None:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ReviewRequired("Use timezone-aware capture times")


@dataclass(frozen=True)
class Window:
    offset: int
    before: bytes
    after: bytes


@dataclass(frozen=True)
class ProgramDelta:
    """An exact full-file inverse, not permission to patch an unknown file."""
    name: str
    original: bytes
    target: bytes
    windows: tuple[Window, ...]

    def __post_init__(self):
        if (not isinstance(self.original, bytes) or not isinstance(self.target, bytes)
                or self.name not in ("AP", "CP") or not self.original or len(self.original) != len(self.target)):
            raise ReviewRequired("Program kind/length differs")
        object.__setattr__(self, "windows", tuple(self.windows))
        forward, inverse = bytearray(self.original), bytearray(self.target)
        end = 0
        for w in self.windows:
            n = len(w.before)
            if type(w.offset) is not int or w.offset < end or not n or n != len(w.after) or w.offset + n > len(forward):
                raise ReviewRequired("Program windows overlap or exceed the file")
            if self.original[w.offset:w.offset+n] != w.before or self.target[w.offset:w.offset+n] != w.after:
                raise ReviewRequired("Program window byte identity differs")
            forward[w.offset:w.offset+n] = w.after
            inverse[w.offset:w.offset+n] = w.before
            end = w.offset + n
        if forward != self.target or inverse != self.original:
            raise ReviewRequired("Unmanifested program changes or incomplete inverse")

    def restore(self, current: bytes) -> bytes:
        if current != self.target:
            raise ReviewRequired("Inverse requires exact complete target bytes")
        result = bytearray(current)
        for w in self.windows:
            result[w.offset:w.offset+len(w.after)] = w.before
        if result != self.original:
            raise ReviewRequired("Complete inverse differs")
        return bytes(result)


@dataclass(frozen=True)
class Field:
    key: int
    before: bytes
    target: bytes

    def __post_init__(self):
        n = 1 if self.key == BASE_KEY else 4
        if (not isinstance(self.before, bytes) or not isinstance(self.target, bytes)
                or self.key not in SLOT_KEYS or len(self.before) != n or len(self.target) != n):
            raise ReviewRequired("Only slot 1's base and eight adjustments may be planned")
        if self.key == BASE_KEY and (self.target != ST or self.before[0] > 11):
            raise ReviewRequired("ST target and a supported FL23 baseline base are required")


@dataclass(frozen=True)
class Resource:
    name: str
    original_sha256: str
    target_sha256: str
    changed_slots: tuple[int, ...] = (1,)

    def __post_init__(self):
        if not self.name.startswith("string_") or not self.name.endswith(".uxc") or "/" in self.name or "\\" in self.name:
            raise ReviewRequired("Unexpected resource path")
        _hash(self.original_sha256); _hash(self.target_sha256)
        if self.changed_slots != (1,):
            raise ReviewRequired("Resource plan must rename only slot 1")


@dataclass(frozen=True)
class Checkpoint:
    body_sha256: str
    capture_id: str
    captured_at: datetime
    program_sha256: Mapping[str, str]
    resources: tuple[Resource, ...]
    fields: tuple[Field, ...]
    independently_reconstructed_copies: int
    normal_usb_return_confirmed: bool
    loaded_ap_matches_fl23: bool
    resources_and_calibration_preserved: bool

    def __post_init__(self):
        object.__setattr__(self, "program_sha256", MappingProxyType(dict(self.program_sha256)))
        object.__setattr__(self, "resources", tuple(self.resources))
        object.__setattr__(self, "fields", tuple(self.fields))
        _hash(self.body_sha256); _time(self.captured_at)
        if not self.capture_id or dict(self.program_sha256) != FL23_SHA256:
            raise ReviewRequired("Checkpoint must contain the validated current FL23 programs")
        if len(self.resources) != RESOURCE_COUNT or len({r.name for r in self.resources}) != RESOURCE_COUNT:
            raise ReviewRequired("Fresh checkpoint must include all 68 unique name resources")
        if {f.key for f in self.fields} != set(SLOT_KEYS) or len(self.fields) != 9:
            raise ReviewRequired("Exactly slot 1's nine selected fields are required")
        if self.independently_reconstructed_copies < 2 or not all((self.normal_usb_return_confirmed,
                self.loaded_ap_matches_fl23, self.resources_and_calibration_preserved)):
            raise ReviewRequired("Checkpoint reconstruction, runtime or preservation evidence is incomplete")


@dataclass(frozen=True)
class Observation:
    body_sha256: str
    session_id: str
    captured_at: datetime
    program_sha256: Mapping[str, str]
    resource_sha256: Mapping[str, str]
    ram_fields: Mapping[int, bytes]
    saved_fields: Mapping[int, bytes]
    # These values must be read from the AP model, not inferred from Backup.
    runtime_bases: Mapping[int, int]
    current_selection: int

    def __post_init__(self):
        for name in ("program_sha256", "resource_sha256", "ram_fields", "saved_fields", "runtime_bases"):
            object.__setattr__(self, name, MappingProxyType(dict(getattr(self, name))))


@dataclass(frozen=True)
class NativeSync:
    body_sha256: str
    session_id: str
    observation_at: datetime
    worker_sha256: str
    reviewed_a7cr_functions: bool
    native_menu_call_completed: bool
    selected_slots: tuple[int, ...]
    unselected_bases_and_calibration_preserved: bool
    before_bases: Mapping[int, int]
    after_bases: Mapping[int, int]
    before_ram_base: bytes
    before_saved_base: bytes
    before_current: int
    after_current: int

    def __post_init__(self):
        object.__setattr__(self, "selected_slots", tuple(self.selected_slots))
        for name in ("before_bases", "after_bases"):
            object.__setattr__(self, name, MappingProxyType(dict(getattr(self, name))))


@dataclass(frozen=True)
class JournalEvent:
    operation: str
    status: str  # intent / verified; no failed/unknown event authorizes replay.


def review_journal(events: Sequence[JournalEvent]) -> tuple[str, ...]:
    pending = None
    completed = []
    for event in events:
        if not event.operation or event.status not in ("intent", "verified"):
            raise ReviewRequired("Unknown journal outcome; preserve the task without replay")
        if event.status == "intent":
            if pending is not None:
                raise ReviewRequired("An earlier mutation has no verified outcome")
            pending = event.operation
        elif pending != event.operation:
            raise ReviewRequired("Receipt has no matching mutation intent")
        else:
            completed.append(pending); pending = None
    if pending is not None:
        raise ReviewRequired("Unresolved mutation intent; do not replay it")
    return tuple(completed)


@dataclass(frozen=True)
class Operation:
    action: str
    scope: str
    expected: str | bytes | int | None = None
    target: str | bytes | int | None = None


@dataclass(frozen=True)
class Plan:
    phase: str
    operations: tuple[Operation, ...]
    preserve_user_fields: tuple[int, ...] = ()
    # Deliberately false: an adapter must bind and verify real native workers.
    executable: bool = False
    physical_recovery_verified: bool = False


def _validate_programs(checkpoint: Checkpoint, programs: Mapping[str, ProgramDelta]) -> None:
    if set(programs) != {"AP", "CP"}:
        raise ReviewRequired("Both complete program deltas are required")
    for kind, item in programs.items():
        if item.name != kind or digest(item.original) != checkpoint.program_sha256[kind]:
            raise ReviewRequired("Program inverse does not return to this FL23 checkpoint")


def validate_fresh(checkpoint: Checkpoint, current: Observation, *, now: datetime,
                   max_age: timedelta = timedelta(minutes=5)) -> None:
    _time(now); _time(current.captured_at)
    if checkpoint.body_sha256 != current.body_sha256 or not current.session_id:
        raise ReviewRequired("Fresh observation is not bound to this camera/session")
    if not checkpoint.captured_at <= current.captured_at <= now or now-current.captured_at > max_age:
        raise ReviewRequired("A fresh post-checkpoint read is required")
    if set(current.program_sha256) != {"AP", "CP"} or set(current.resource_sha256) != {r.name for r in checkpoint.resources}:
        raise ReviewRequired("Full programs and all 68 resources must be freshly read")
    for value in (*current.program_sha256.values(), *current.resource_sha256.values()): _hash(value)
    if set(current.runtime_bases) != set(range(1, 7)) or any(type(v) is not int or not 0 <= v <= 11 for v in current.runtime_bases.values()):
        raise ReviewRequired("All six native AP bases must be observed independently")
    if type(current.current_selection) is not int or not 0 <= current.current_selection <= 17:
        raise ReviewRequired("Unsupported current Creative Look selector")
    for field in checkpoint.fields:
        n = len(field.before)
        if len(current.ram_fields.get(field.key, b"")) != n or len(current.saved_fields.get(field.key, b"")) != n:
            raise ReviewRequired("Selected setting readback is incomplete")


def classify(checkpoint: Checkpoint, current: Observation,
             targets: Mapping[str, str]) -> str:
    """Classify complete readback only; a known hash is not a retry receipt."""
    if set(targets) != {"AP", "CP"}: raise ReviewRequired("Both target hashes are required")
    labels = []
    for kind in ("AP", "CP"):
        value = current.program_sha256.get(kind)
        if value == checkpoint.program_sha256[kind]: labels.append("original")
        elif value == targets[kind]: labels.append("target")
        else: return "UNKNOWN"
    names = []
    for item in checkpoint.resources:
        value = current.resource_sha256.get(item.name)
        if value == item.original_sha256: names.append("original")
        elif value == item.target_sha256: names.append("target")
        else: return "UNKNOWN"
    if labels == ["original", "original"] and set(names) == {"original"}: return "FL23_ORIGINAL"
    if labels == ["target", "target"] and set(names) == {"target"}: return "IMPORTED_FILES"
    if labels == ["original", "target"] and set(names) == {"original"}: return "CP_ONLY"
    if labels == ["original", "target"] and set(names) == {"target"}: return "CP_AND_NAMES"
    return "PARTIAL_KNOWN"


def require_native_st(checkpoint: Checkpoint, current: Observation, sync: NativeSync,
                      reviewed_worker_sha256: str, *, global_st: bool) -> None:
    """Do not substitute saved/RAM Backup values for native-model evidence."""
    _hash(reviewed_worker_sha256)
    if (sync.body_sha256 != checkpoint.body_sha256 or sync.session_id != current.session_id
            or sync.observation_at != current.captured_at or sync.worker_sha256 != reviewed_worker_sha256):
        raise ReviewRequired("Native ST synchronization receipt is stale or from another worker/body")
    if not all((sync.reviewed_a7cr_functions, sync.native_menu_call_completed,
                sync.unselected_bases_and_calibration_preserved)) or sync.selected_slots != (1,):
        raise ReviewRequired("Reviewed A7CR native menu synchronization is required")
    if (set(sync.before_bases) != set(range(1, 7)) or dict(sync.after_bases) != dict(current.runtime_bases)
            or any(sync.before_bases[s] != sync.after_bases[s] for s in range(2, 7))):
        raise ReviewRequired("Native setter changed an unselected slot or omitted its model readback")
    if any(type(v) is not int or not 0 <= v <= 11 for v in sync.before_bases.values()):
        raise ReviewRequired("Pre-sync native base values are outside the reviewed range")
    if (len(sync.before_ram_base) != 1 or sync.before_ram_base != sync.before_saved_base
            or sync.before_saved_base[0] > 11):
        raise ReviewRequired("Preserve a complete saved/RAM base read before native deactivation")
    if current.runtime_bases[1] != 0 or current.ram_fields[BASE_KEY] != ST or current.saved_fields[BASE_KEY] != ST:
        raise ReviewRequired("Selected base is not ST in native, RAM and saved state")
    if sync.after_current != current.current_selection:
        raise ReviewRequired("Current selection does not match the native receipt")
    if sync.before_current != sync.after_current:
        raise ReviewRequired("Slot-base synchronization must not mutate the current selection")
    if global_st and current.current_selection != 0:
        raise ReviewRequired("Owner must select global ST; verify native current==0 before removing support")


def staging_plan(checkpoint: Checkpoint, current: Observation, *, now: datetime) -> Plan:
    """Slot-only saved-setting stage; real native synchronization remains a gate."""
    validate_fresh(checkpoint, current, now=now)
    if dict(current.program_sha256) != dict(checkpoint.program_sha256) or any(
            current.resource_sha256[r.name] != r.original_sha256 for r in checkpoint.resources):
        raise ReviewRequired("ST staging only accepts a fresh unmodified FL23 checkpoint")
    steps = []
    for field in checkpoint.fields:
        if current.ram_fields[field.key] != field.before or current.saved_fields[field.key] != field.before:
            raise ReviewRequired("Selected recipe changed since the fresh checkpoint")
        if field.before != field.target:
            steps.append(Operation("compare_and_stage_selected", f"setting:{field.key:08x}", field.before, field.target))
    steps += [Operation("save_selected_and_full_readback", "slot:1"),
              Operation("native_menu_sync_and_independent_readback", "slot:1"),
              Operation("verify_fresh_unselected_and_calibration_preservation", "settings")]
    return Plan("OFFLINE_ST_STAGING_ORDER_ONLY", tuple(steps))


def install_plan(checkpoint: Checkpoint, programs: Mapping[str, ProgramDelta],
                 current: Observation, sync: NativeSync, *, reviewed_worker_sha256: str,
                 battery_percent: int, now: datetime, journal: Sequence[JournalEvent] = ()) -> Plan:
    """Plan a first installation only. Known partial states are never replayed."""
    _validate_programs(checkpoint, programs)
    validate_fresh(checkpoint, current, now=now)
    completed = review_journal(journal)
    if type(battery_percent) is not int or not MIN_BATTERY <= battery_percent <= 100:
        raise ReviewRequired("Fresh battery confirmation must be at least 75 percent")
    targets = {k:digest(v.target) for k,v in programs.items()}
    if classify(checkpoint, current, targets) != "FL23_ORIGINAL" or completed:
        raise ReviewRequired("First install cannot replay an existing or partial transaction")
    require_native_st(checkpoint, current, sync, reviewed_worker_sha256, global_st=False)
    if any(current.ram_fields[f.key] != f.target or current.saved_fields[f.key] != f.target
           for f in checkpoint.fields):
        raise ReviewRequired("All selected fields must be staged and verified before LUT programs")
    # Each stage must independently verify complete bytes before the next stage.
    steps = [Operation("native_st_already_verified", "slot:1")]
    steps.append(Operation("write_and_full_readback", "CP", checkpoint.program_sha256["CP"], targets["CP"]))
    steps.extend(Operation("rename_and_full_readback", "resource:"+r.name, r.original_sha256, r.target_sha256) for r in checkpoint.resources if r.original_sha256 != r.target_sha256)
    steps.append(Operation("write_and_full_readback", "AP", checkpoint.program_sha256["AP"], targets["AP"]))
    steps += [Operation("one_shot_if_needed", "WBI"), Operation("await_cold_start", "power"),
              Operation("verify_loaded_ap_and_all_files", "runtime"), Operation("owner_preview_photo_acceptance", "slot:1")]
    return Plan("OFFLINE_INSTALL_ORDER_ONLY", tuple(steps))


def recovery_plan(checkpoint: Checkpoint, programs: Mapping[str, ProgramDelta],
                  current: Observation, sync: NativeSync, *, reviewed_worker_sha256: str,
                  battery_percent: int, now: datetime, journal: Sequence[JournalEvent] = ()) -> Plan:
    """Restore only known owned bytes and CAS-restore selected slot settings.

    A later user adjustment is kept. Names/programs outside known old/new file
    identities stop the plan; they are never replaced by a historical snapshot.
    The owner physically selects global ST; native current==0 must have been
    observed before support is removed. No current-selection setter is assumed.
    """
    _validate_programs(checkpoint, programs)
    validate_fresh(checkpoint, current, now=now)
    review_journal(journal)
    if type(battery_percent) is not int or not MIN_BATTERY <= battery_percent <= 100:
        raise ReviewRequired("Fresh battery confirmation must be at least 75 percent")
    targets = {k:digest(v.target) for k,v in programs.items()}
    state = classify(checkpoint, current, targets)
    if state == "UNKNOWN": raise ReviewRequired("Unknown program/resource bytes; do not overwrite")
    require_native_st(checkpoint, current, sync, reviewed_worker_sha256, global_st=True)
    steps = [Operation("native_global_st_already_verified", "selection")]
    # Restoring AP first removes marker production before CP table support.
    for kind in ("AP", "CP"):
        if current.program_sha256[kind] == targets[kind]:
            steps.append(Operation("inverse_and_full_readback", kind, targets[kind], checkpoint.program_sha256[kind]))
    for resource in checkpoint.resources:
        if current.resource_sha256[resource.name] == resource.target_sha256 != resource.original_sha256:
            steps.append(Operation("inverse_and_full_readback", "resource:"+resource.name,
                                   resource.target_sha256, resource.original_sha256))
    preserved = []
    for field in checkpoint.fields:
        ram, saved = current.ram_fields[field.key], current.saved_fields[field.key]
        if ram != saved:
            raise ReviewRequired("Selected RAM/storage diverged; preserve unsaved user edits")
        if field.key == BASE_KEY:
            # Deactivation temporarily staged ST. The fresh native receipt
            # retains the prior saved/RAM value, so a later user-chosen base is
            # reapplied after support removal rather than lost to the old backup.
            prior = sync.before_saved_base
            desired = field.before if prior == field.target else prior
            if prior not in (field.before, field.target): preserved.append(field.key)
            if desired != ST:
                steps.append(Operation("restore_selected_base_via_native_menu", "slot:1", ST, desired))
        elif ram == field.target and field.before != field.target:
            steps.append(Operation("compare_and_restore_selected", f"setting:{field.key:08x}", ram, field.before))
        elif ram != field.before:
            preserved.append(field.key)
    steps += [Operation("sync_restored_selected_via_native_menu", "slot:1"),
              Operation("verify_fresh_unselected_and_calibration_preservation", "settings"),
              Operation("one_shot_if_needed", "WBI"), Operation("await_cold_start", "power"),
              Operation("verify_loaded_fl23_and_all_files", "runtime"),
              Operation("owner_fl23_and_other_five_slots_acceptance", "physical"),
              Operation("owner_choose_supported_selection_after_restore", "selection")]
    return Plan("OFFLINE_RECOVERY_ORDER_ONLY", tuple(steps), tuple(sorted(preserved)))
