"""A local completion review cannot bless unknown/partial writes. No USB."""
from copy import deepcopy
from types import SimpleNamespace
import unittest
import review_portrait_exit_timeout as m


def fixture():
    p=SimpleNamespace(programs={'candidate':{'AP':b'full AP','CP':b'full CP'}})
    state={'phase':'STOPPED_INSPECTION_REQUIRED','error_type':'TimeoutError','error':m.ERROR}
    events=[{'phase':'portrait_slots_command_started','command':'install','battery_percent':90},
            {'phase':'DEVICE_PREFLIGHT_PASSED'}, {'phase':'PORTRAIT_SLOTS_SAVED_AND_NATIVE_ST_VERIFIED'}]
    def stage(kind):
        events.extend([{'phase':'native_invocation_intent','worker':kind,'mode':1},
                       {'phase':'native_invocation_returned','worker':kind,'mode':1,'report':{'ok':True}},
                       {'phase':'native_cleanup_verified','worker':kind,'mode':1}])
    stage('cp_stage')
    events += [{'phase':'portrait_slots_names_invocation_intent','mode':1},
               {'phase':'portrait_slots_names_invocation_returned','mode':1,'report':{'files':68,'native_verified':True}},
               {'phase':'all_68_resource_bytes_verified','state':'named'}]
    stage('ap_stage')
    for chip,raw in p.programs['candidate'].items():
        events.append({'phase':'complete_program_byte_readback','tag':'after-ap','chip':chip,'bytes':len(raw),'sha256':m.sha(raw)})
    events += [{'phase':'program_state_verified','tag':'after-ap','state':'installed'}]
    stage('wbi_stage')
    events += [{'phase':'service_exit_intent'},{'phase':'service_exit_returned'},dict(state)]
    return p,state,events


class CompletionReview(unittest.TestCase):
    def test_complete_history_admitted_without_mutation(self):
        p,s,e=fixture();old=deepcopy(e);m.require_complete_log(e,s,p);self.assertEqual(e,old)
    def test_missing_wbi_or_program_cleanup_rejected(self):
        for worker in ('cp_stage','ap_stage','wbi_stage'):
            p,s,e=fixture();e=[x for x in e if not (x['phase']=='native_cleanup_verified' and x['worker']==worker)]
            with self.subTest(worker=worker),self.assertRaises(ValueError):m.require_complete_log(e,s,p)
    def test_unknown_native_result_rejected(self):
        p,s,e=fixture();e.insert(-3,{'phase':'native_invocation_intent','worker':'wbi_stage','mode':1})
        with self.assertRaises(ValueError):m.require_complete_log(e,s,p)
    def test_missing_complete_readback_rejected(self):
        p,s,e=fixture();e=[x for x in e if x['phase']!='complete_program_byte_readback' or x['chip']!='CP']
        with self.assertRaises(ValueError):m.require_complete_log(e,s,p)
    def test_other_timeout_cannot_be_reclassified(self):
        p,s,e=fixture();s['error']='Unknown write outcome'
        with self.assertRaises(ValueError):m.require_complete_log(e,s,p)
    def test_partial_name_transaction_rejected(self):
        p,s,e=fixture();next(x for x in e if x['phase']=='portrait_slots_names_invocation_returned')['report']['files']=67
        with self.assertRaises(ValueError):m.require_complete_log(e,s,p)
    def test_false_native_success_rejected(self):
        p,s,e=fixture();next(x for x in e if x['phase']=='native_invocation_returned')['report']['ok']=False
        with self.assertRaises(ValueError):m.require_complete_log(e,s,p)
    def test_absent_service_exit_rejected(self):
        p,s,e=fixture();e=[x for x in e if x['phase']!='service_exit_returned']
        with self.assertRaises(ValueError):m.require_complete_log(e,s,p)


if __name__=='__main__':unittest.main()
