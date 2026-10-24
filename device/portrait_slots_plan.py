"""Incremental portrait-slot scope and recovery to the current CC baseline.

Pure planning/preservation helpers only. Slot 1 Classic Chrome, slots 4–6,
native FL2/FL3 and body calibration are never restore targets here. Unknown
outcomes stop; these helpers do not implement a transport or a rescue mode.
"""
from __future__ import annotations

import re
from fl23_install import preserved

SLOTS=(2,3)
SOURCE_HASHES={'AP':'585c9bf786600c24926f29432cf263c2e2ee76a8d00975e249c57641dfb56c71',
               'CP':'8d006427e0279beaad957a5d811e9237b6105afbb8c7c88b6be715bc91e58a82'}
BASE_KEYS={slot:0x02CF0CD0+2*(slot-1) for slot in SLOTS}
SLOT_KEYS={slot:(BASE_KEYS[slot],)+tuple(0x02CF0CF0+2*(slot-1)+0x20*i for i in range(8)) for slot in SLOTS}
SELECTED_KEYS=frozenset(key for keys in SLOT_KEYS.values() for key in keys)
COMPANION_KEYS={slot:BASE_KEYS[slot]+1 for slot in SLOTS}
NATIVE_INDICES={slot:slot+9 for slot in SLOTS}


class ReviewRequired(ValueError):pass


def slot_fields(ap,ram,saved):
    # The checkpoint owns descriptor derivation. Import lazily to keep one
    # exact implementation and avoid transport side effects at module import.
    from portrait_slots_checkpoint import slot_fields as derive
    result=derive(ap,ram,saved);validate_fields(result);return result


def validate_fields(fields):
    if len(fields)!=18 or {f.get('key') for f in fields}!=set(SELECTED_KEYS):
        raise ReviewRequired('Only the two portrait slots, exactly eighteen fields, are allowed')
    for field in fields:
        slot,key=field.get('slot'),field.get('key')
        if slot not in SLOTS or key not in SLOT_KEYS[slot]:raise ReviewRequired('Field belongs to another slot')
        n=1 if key==BASE_KEYS[slot] else 4
        try:before_ram,before_saved,target=(bytes.fromhex(field[name]) for name in ('before_ram','before_saved','after'))
        except (ValueError,TypeError,KeyError):raise ReviewRequired('Selected field encoding is incomplete')
        if any(len(value)!=n for value in (before_ram,before_saved,target)) or before_ram!=before_saved:
            raise ReviewRequired('Preserve selected unsaved edits or malformed values')
        if n==1 and (before_saved[0]>11 or target!=b'\0'):
            raise ReviewRequired('Portrait base requires supported current-CC source and ST target')
    return True


def selected_preservation(before,after,expected,*,native_targets=None):
    """Permit only selected fields and their target-valued native array copies."""
    if not set(expected)<=set(SELECTED_KEYS):raise ReviewRequired('Write/preservation scope extends beyond slots2/3')
    native_targets=native_targets or {}
    if any(slot not in SLOTS or type(value) is not int or not 0<=value<=11 for slot,value in native_targets.items()):
        raise ReviewRequired('Only bounded slot2/3 native targets may affect copies')
    neutral=[dict(after[0]),after[1]]
    for key,value in expected.items():
        slot=next(slot for slot,keys in SLOT_KEYS.items() if key in keys)
        n=1 if key==BASE_KEYS[slot] else 4
        old,new=before[0][key],after[0][key]
        if not isinstance(value,bytes) or len(value)!=n or (n==1 and value[0]>11) or new.data!=value or old.attr!=new.attr:
            raise ReviewRequired('Selected field readback differs')
        neutral[0][key]=old
    for slot,key in COMPANION_KEYS.items():
        old,new=before[0].get(key),after[0].get(key)
        if old is None or new is None:
            if old is not new:raise ReviewRequired('Native selected array disappeared')
        elif (old.data,old.attr)!=(new.data,new.attr):
            target=native_targets.get(slot)
            if (target is None or old.attr!=0xc0 or old.attr!=new.attr or len(old.data)!=13 or len(new.data)!=13
                    or any(a!=b and b!=target for a,b in zip(old.data,new.data))):
                raise ReviewRequired('Unreviewed native selected-array change')
            neutral[0][key]=old
    result=preserved(before,neutral,{})
    result['selected_portrait_fields_verified']=len(expected)
    result['preserved_slots']=[1,4,5,6]
    return result


def restore_values(fields,ram,saved):
    """CAS policy: return current-CC values only while imported values are owned."""
    validate_fields(fields);desired={};kept=[]
    for field in fields:
        key=field['key'];value=ram[0][key].data
        n=1 if key in BASE_KEYS.values() else 4
        if (len(value)!=n or len(saved[0][key].data)!=n
                or ram[0][key].attr!=saved[0][key].attr):
            raise ReviewRequired('Current selected field layout differs')
        if value!=saved[0][key].data:raise ReviewRequired('Unsaved selected user edit prevents SAVE3 restore')
        imported=bytes.fromhex(field['after'])
        if value==imported:desired[key]=bytes.fromhex(field['before_saved'])
        else:desired[key]=value;kept.append(key)
        if key in BASE_KEYS.values() and (len(desired[key])!=1 or desired[key][0]>11):
            raise ReviewRequired('Restoration base is outside native current-CC support')
    return desired,tuple(sorted(kept))


def validate_probe(probe,*,require_global_st=False):
    before,after=probe.get('before_bases'),probe.get('after_bases')
    if (probe.get('read_only') is not True or not isinstance(before,list) or len(before)!=18 or before!=after
            or any(type(v) is not int or not 0<=v<=11 for v in before) or probe.get('changed_mask')!=0
            or type(probe.get('current')) is not int or not 0<=probe['current']<=17
            or probe['current']!=probe.get('after_current') or type(probe.get('pid')) is not int or probe['pid']<=0
            or type(probe.get('base')) is not int or probe['base']<=0
            or re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n',probe.get('boot_id','')) is None):
        raise ReviewRequired('Independent complete read-only AP model evidence is required')
    if require_global_st and probe['current']!=0:raise ReviewRequired('Owner must select global ST before portrait mutations')
    return True


def validate_reprobe(previous,fresh,slot,allowed,*,require_global_st=True):
    """After saved-ST, native selected value can stay old or already be target."""
    validate_probe(previous,require_global_st=require_global_st);validate_probe(fresh,require_global_st=require_global_st)
    if slot not in SLOTS or not allowed or any(type(v) is not int or not 0<=v<=11 for v in allowed):
        raise ReviewRequired('Only slot2/3 bounded reprobe transitions are supported')
    if any(previous[key]!=fresh[key] for key in ('pid','base','boot_id','current')):
        raise ReviewRequired('Native process/current changed during staging')
    index=NATIVE_INDICES[slot]
    for i,(old,new) in enumerate(zip(previous['before_bases'],fresh['before_bases'])):
        if (i==index and new not in allowed) or (i!=index and new!=old):
            raise ReviewRequired('Saved stage changed CC or another unselected native base')
    return True


def classify_programs(actual,target):
    if set(actual)!={'AP','CP'} or set(target)!={'AP','CP'}:raise ReviewRequired('Both full program identities are required')
    labels=[]
    for kind in ('AP','CP'):
        if actual[kind]==SOURCE_HASHES[kind]:labels.append('source')
        elif actual[kind]==target[kind]:labels.append('target')
        else:return 'unknown'
    return {('source','source'):'original',('source','target'):'cp_only',('target','target'):'installed'}.get(tuple(labels),'unknown')


def recovery_steps(state,*,named=True):
    """Non-executable order, recovering mask7 → current mask1 Classic Chrome."""
    if state not in ('original','cp_only','installed'):raise ReviewRequired('Unknown program state: inspect, do not replay')
    steps=[{'action':'owner_select_global_ST_and_native_readback','persistent_write':False},
           {'action':'read_current_selected_values_and_preflight_both_catalog_paths','slots':[2,3]},
           {'action':'save_ST_reprobe_and_guarded_native_sync','slots':[2,3],'preserve_slots':[1,4,5,6]}]
    if state=='installed':steps.append({'action':'inverse_program','component':'AP','mode':2,'after':'cp_only'})
    if state in ('installed','cp_only'):steps.append({'action':'inverse_program','component':'CP','mode':2,'after':'original'})
    if named:steps.append({'action':'inverse_only_added_names_after_source_AP','mode':2,'preserve_name':'Classic Chrome'})
    steps += [{'action':'CAS_restore_current_CC_selected_values_or_keep_later_user_edits','slots':[2,3]},
              {'action':'saved_restore_reprobe_then_guarded_native_sync_or_independent_already_coherent','slots':[2,3]},
              {'action':'fresh_unselected_and_calibration_preservation'},
              {'action':'invalidate_WBI_only_if_needed_then_cold_start'},
              {'action':'verify_loaded_CC_source_all_resources_saved_native_bases_and_owner_photos'}]
    return {'recover_to_program_sha256':dict(SOURCE_HASHES),'recover_to':'CURRENT_MACHINE_VERIFIED_CLASSIC_CHROME_MASK1',
            'slots':[2,3],'preserve_slots':[1,4,5,6],'preserve_native_looks':['FL','FL2','FL3'],
            'steps':steps,'executable':False,'physical_recovery_verified':False,'whole_snapshot_restore':False}
