"""Agent-neutral project commands; JSON stdout, private logs, explicit USB actions."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime,timezone
from contextlib import contextmanager
import stat

from .project_paths import ENV,SCHEMA,source_root

JOBS={'single':'private/single-slot-install/classic-chrome',
      'portrait':'private/portrait-slots-install/portrait'}
OPERATIONS=('build-assets','checkpoint','prepare','native-check','finalize','validate','install','verify','restore','inspect-exit','review-exit')
USB_OPERATIONS=frozenset(('checkpoint','install','verify','restore','review-exit'))
WRITE_OPERATIONS=frozenset(('install','restore'))


def _lock_path(uid):return '/tmp/a7cr-creative-look-usb-'+str(uid)+'.lock'


@contextmanager
def host_usb_lock():
    """Serialize all public camera commands, including across private projects."""
    import fcntl
    uid=int(os.environ.get('SUDO_UID',os.getuid()))
    flags=os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(_lock_path(uid),flags,0o600)
    with os.fdopen(fd,'a') as lock:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0,uid) or info.st_mode&0o022:
            raise PermissionError('Untrusted host USB lock file')
        if os.geteuid()==0 and uid>0 and info.st_uid==0:
            os.fchown(fd,uid,int(os.environ.get('SUDO_GID',os.getgid())))
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield


def _json(path):return json.loads(path.read_text())


def project_root(path):
    raw=Path(path)
    if raw.is_symlink():raise ValueError('Do not select a symlink as a project root')
    root=raw.resolve();data=_json(root/'project.json')
    if (data.get('schema')!=SCHEMA or data.get('model')!='ILCE-7CR' or data.get('firmware')!='2.01'
            or data.get('preset')!='fujifilm-portrait'):
        raise ValueError('Unsupported project manifest')
    # Executable sources are always this checkout; a project cannot replace
    # the runner with a path supplied in JSON.
    for name in ('device','offline','tools','tests','research'):
        if (root/name).resolve()!=(source_root()/name).resolve():
            raise ValueError('Project source/dependency link changed: '+name)
    if (root/'private').is_symlink() or (root/'private').resolve().parent!=root:
        raise ValueError('Private project data must remain inside this project')
    return root


def initialize(path,firmware):
    if firmware!='2.01':raise ValueError('Only owner-confirmed A7CR 2.01 is supported')
    raw=Path(path);root=raw.resolve();code=source_root()
    if raw.is_symlink() or root.exists() or root==code or root in code.parents:
        raise ValueError('Choose a new private project directory; never overwrite an existing tree')
    os.umask(0o077);root.mkdir(parents=True,mode=0o700)
    try:
        (root/'private').mkdir(mode=0o700)
        (code/'research').mkdir(exist_ok=True)
        for name in ('device','offline','tools','tests','research','upstream.lock.json','requirements.txt','requirements-research.txt'):
            (root/name).symlink_to(code/name,target_is_directory=(code/name).is_dir())
        manifest={'schema':SCHEMA,'model':'ILCE-7CR','firmware':'2.01','preset':'fujifilm-portrait',
                  'active_names':{'1':'Classic Chrome','2':'PRO Neg. Std','3':'ASTIA / SOFT'},
                  'firmware_version_is_owner_declaration':True,'camera_identified':False,
                  'camera_opened':False,'installation_authorized':False}
        (root/'project.json').write_text(json.dumps(manifest,indent=2)+'\n')
    except BaseException:
        # Keep a partial initialization for inspection; never delete user data.
        raise
    return {'ok':True,'project':str(root),'schema':SCHEMA,'camera_opened':False,'next':'status'}


def status(path):
    root=project_root(path);jobs={}
    for stage,relative in JOBS.items():
        folder=root/relative;state=folder/'state.private.json';manifest=folder/'package.private.json'
        jobs[stage]={'package_present':manifest.is_file(),'recorded_phase':_json(state).get('phase') if state.is_file() else 'NOT_PREPARED'}
    return {'ok':True,'project':str(root),'jobs':jobs,'camera_opened':False,
            'status_is_not_artifact_validation':True,
            'requires_local_reviewed_artifacts':True,'arbitrary_camera_installer':False}


def command(root,stage,operation,*,battery=None,checkpoint=None):
    """Pure argument construction. No imports of USB or camera backends."""
    if stage not in JOBS or operation not in OPERATIONS:raise ValueError('Unknown workflow stage or operation')
    if operation in WRITE_OPERATIONS and (type(battery) is not int or not 75<=battery<=100):
        raise ValueError('Install/restore require fresh on-camera battery confirmation, 75–100')
    if operation in ('inspect-exit','review-exit') and stage!='portrait':
        raise ValueError('Exit-timeout review currently supports the tested portrait extension only')
    code=source_root();job=root/JOBS[stage]
    python=[sys.executable]
    def script(folder,name,*args):return python+[str(code/folder/name),*map(str,args)]
    if operation=='build-assets':return script('offline','build_project_assets.py','--stage',stage)
    if operation=='checkpoint':
        stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        if stage=='single':
            parent=root/'private/single-slot-checkpoints'
            return script('device','single_slot_checkpoint.py','--probe',root/'private/single-slot-runtime/probe-v2/worker.private.json','--destination',parent/('read-'+stamp))
        parent=root/'private/portrait-slots-checkpoints'
        return script('device','portrait_slots_checkpoint.py','--destination',parent/('read-'+stamp))
    prefix='single_slot' if stage=='single' else 'portrait_slots'
    if operation=='prepare':
        if checkpoint is None:raise ValueError('Preparation requires an explicitly selected complete checkpoint')
        capture=Path(checkpoint).resolve()
        if (root/'private').resolve() not in capture.parents or capture.is_symlink():
            raise ValueError('Use a checkpoint inside this private project')
        return script('offline','prepare_'+prefix+'_installation.py','--checkpoint',capture,'--output',job)
    if operation=='native-check':return script('offline','check_'+prefix+'_installation.py','--package',job/'package.private.json')
    if operation in ('finalize','validate'):
        args=['--workspace',job]+(['--finalize'] if operation=='finalize' else [])
        return script('offline','finalize_'+prefix+'.py',*args)
    if operation in ('inspect-exit','review-exit'):
        args=['--workspace',job]+(['--verify'] if operation=='review-exit' else [])
        return script('device','review_portrait_exit_timeout.py',*args)
    args=['--workspace',job,'--command',operation]
    if operation in WRITE_OPERATIONS:args+=['--battery-percent',str(battery)]
    return script('device',prefix+'_install.py',*args)


def run(path,stage,operation,*,battery=None,checkpoint=None):
    root=project_root(path)
    # Reject insufficient power before constructing a backend or opening USB.
    if operation in WRITE_OPERATIONS and (type(battery) is not int or not 75<=battery<=100):
        raise ValueError('Fresh on-camera battery confirmation must be 75–100')
    if operation in USB_OPERATIONS:
        if sys.platform!='darwin':raise ValueError('Physical camera commands are validated on macOS only')
        if os.geteuid()!=0:raise PermissionError('Run this explicit camera operation with sudo in your own terminal')
    os.umask(0o077)
    logs=root/'private/agent-logs';logs.mkdir(parents=True,exist_ok=True)
    if logs.is_symlink() or (root/'private').resolve() not in logs.resolve().parents:
        raise ValueError('Private log directory escapes this project')
    if os.geteuid()==0 and os.environ.get('SUDO_UID','').isdigit():
        os.chown(logs,int(os.environ['SUDO_UID']),int(os.environ.get('SUDO_GID','0')))
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    log=logs/(stage+'-'+operation+'-'+stamp+'.log')
    argv=command(root,stage,operation,battery=battery,checkpoint=checkpoint)
    env=dict(os.environ);env[ENV]=str(root)
    env['PYTHONPATH']=os.pathsep.join((str(source_root()),str(source_root()/'device'),str(source_root()/'offline')))
    # One host-wide lock across projects/users of the same camera owner. Sudo
    # and non-sudo invocations resolve to the same owner id, without HOME guesses.
    lock=None
    try:
        if operation in USB_OPERATIONS:
            lock=host_usb_lock();lock.__enter__()
        print('Running '+stage+'/'+operation+'; private log: '+str(log),file=sys.stderr,flush=True)
        with log.open('xb') as stream:
            result=subprocess.run(argv,cwd=root,env=env,stdout=stream,stderr=subprocess.STDOUT)
        return {'ok':result.returncode==0,'stage':stage,'operation':operation,'returncode':result.returncode,
                'log':str(log),'camera_action_requested':operation in USB_OPERATIONS,
                'persistent_camera_write_requested':operation in WRITE_OPERATIONS,
                'automatic_retry':False}
    finally:
        if lock is not None:lock.__exit__(None,None,None)
        if os.geteuid()==0 and os.environ.get('SUDO_UID','').isdigit() and log.exists():
            os.chown(log,int(os.environ['SUDO_UID']),int(os.environ.get('SUDO_GID','0')))


def fit_profiles(path,profiles,*,use_upstream_model=False):
    """Fit explicitly supplied preset profiles offline; no asset downloads."""
    import hashlib
    import shutil
    root=project_root(path)
    if use_upstream_model is not True:raise ValueError('Explicit acceptance of the provisional upstream model is required')
    specs={1:('Sony_ILCE-7CM2_Classic_Chrome.dcp','0999cb3b7860de4fb75ec9d74bd22a0786a77889f75fdb635efc02c72dd51f30','Classic Chrome'),
           2:('Sony_ILCE-7CM2_Pro_Neg_Std.dcp','87de86140f7374d17f44cbdd384fbadca1cc99485dc932fcaf2c9125f20fd826','PRO Neg. Std'),
           3:('Sony_ILCE-7CM2_Astia.dcp','29a82bf333be8b38fce4ada82999c21041414d3e5887bff1c1ac4a1180fd433f','ASTIA / SOFT')}
    if set(profiles)!={1,2,3}:raise ValueError('Supply the three explicit local preset profiles')
    for slot,(_,digest,_) in specs.items():
        if hashlib.sha256(Path(profiles[slot]).read_bytes()).hexdigest()!=digest:
            raise ValueError('Local profile differs from the reviewed preset input: slot '+str(slot))
    folders={1:root/'private/single-slot-input',2:root/'private/portrait-inputs',3:root/'private/portrait-inputs'}
    if any(folder.exists() for folder in set(folders.values())):
        raise ValueError('Preserve existing input/fit evidence; use a fresh project or inspect it')
    os.umask(0o077);provenance=[]
    for folder in set(folders.values()):folder.mkdir(parents=True,mode=0o700)
    for slot,(filename,digest,name) in specs.items():
        folder=folders[slot];local=folder/filename;shutil.copyfile(profiles[slot],local)
        output=folder/('fit' if slot==1 else 'fit-slot'+str(slot))
        argv=[sys.executable,str(source_root()/'a7cr.py'),'fit-dcp',str(local),'--slot',str(slot),
              '--name',name,'--use-upstream-model','--output',str(output)]
        with (folder/('fit-slot'+str(slot)+'.log')).open('xb') as log:
            subprocess.run(argv,cwd=root,stdout=log,stderr=subprocess.STDOUT,check=True)
        provenance.append({'slot':slot,'file':filename,'sha256':digest,'name':name})
    (folders[2]/'provenance.private.json').write_text(json.dumps({
        'schema':'a7cr-local-preset-profile-provenance/1','profiles':provenance,
        'downloaded_by_tool':False,'source':'Owner-supplied unchanged QAQLeonard profile release inputs',
        'model':'Explicitly accepted provisional upstream model; not measured A7CR color calibration'},indent=2)+'\n')
    return {'ok':True,'fitted_slots':[1,2,3],'camera_opened':False,'firmware_generated':False,'installable':False}
