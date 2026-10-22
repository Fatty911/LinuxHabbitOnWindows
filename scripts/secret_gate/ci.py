import ctypes

import hashlib

import importlib.util

import json

import os

from pathlib import Path

import re

import resource

import selectors

import shutil

import signal

import subprocess

import sys

import tempfile

import time

class Failure(Exception): pass

def sha(raw): return hashlib.sha256(raw).hexdigest()

def require(ok, code):
    if not ok: raise Failure(code)

def process_limits():
    resource.setrlimit(resource.RLIMIT_AS,(AS_LIMIT,AS_LIMIT))
    resource.setrlimit(resource.RLIMIT_DATA,(512*1024**2,512*1024**2))
    resource.setrlimit(resource.RLIMIT_CPU,(120,120))
    resource.setrlimit(resource.RLIMIT_FSIZE,(32*1024**2,32*1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE,(128,128))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    os.umask(0o077)

def reap_descendants():
    # Git helper intentionally starts new sessions, so killpg alone is insufficient.
    # Subreaper adopts those children after worker death; no repository code runs.
    deadline=time.monotonic()+5
    while True:
        children=[]
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit(): continue
            try:
                # Read only numeric process ancestry, never cmdline/environ.
                fields=(entry/'stat').read_text().rsplit(')',1)[1].split()
                if int(fields[1])==os.getpid(): children.append(entry.name)
            except FileNotFoundError: pass
        for child in children:
            try: os.kill(int(child),signal.SIGKILL)
            except ProcessLookupError: pass
        while True:
            try:
                pid,_=os.waitpid(-1,os.WNOHANG)
                if pid==0: break
            except ChildProcessError: return
        require(time.monotonic()<deadline,'cleanup-child-timeout')
        time.sleep(.01)

BASE = Path(__file__).resolve().parent
AS_LIMIT = 8 * 1024**3
OUTPUT_LIMIT = 8 * 1024**2
REPOSITORY = 'Fatty911/LinuxHabbitOnWindows'
FIXTURE_SECONDS = 120
SCAN_SECONDS = 180

def public_event():
    require(os.environ.get('GITHUB_REPOSITORY') == REPOSITORY, 'public-repository-required')
    event_path = os.environ.get('GITHUB_EVENT_PATH', '')
    with open(event_path, 'rb') as f: raw = f.read(8*1024**2+1)
    require(len(raw)<=8*1024**2, 'event-size')
    event = json.loads(raw)
    repository = event.get('repository', {})
    require(repository.get('full_name') == REPOSITORY and repository.get('private') is False and repository.get('visibility') == 'public', 'public-repository-required')
    revision = os.environ.get('GITHUB_SHA', '')
    require(re.fullmatch('[a-f0-9]{40}', revision), 'exact-event-commit-required')
    name = os.environ.get('GITHUB_EVENT_NAME')
    if name == 'push': require(event.get('after') == revision, 'event-commit-mismatch')
    elif name == 'pull_request': require(event.get('pull_request', {}).get('merge_commit_sha') == revision, 'event-commit-mismatch')
    else: raise Failure('unsupported-event')
    return revision

def supervise(mode, revision):
    require(ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)==0,'subreaper-unavailable')
    directory=Path(tempfile.mkdtemp(prefix='bounded-secret-ci-'))
    proc=None; output=bytearray()
    try:
        binary=os.environ.get('PUBLIC_SECRET_GITLEAKS','')
        require(Path(binary).is_absolute(),'scanner-path-required')
        env={'PATH':os.defpath,'HOME':str(directory),'TMPDIR':str(directory),'LC_ALL':'C','PUBLIC_SECRET_GITLEAKS':binary,'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,'GIT_TERMINAL_PROMPT':'0'}
        if mode=='fixtures':
            command=[sys.executable,'-I','-B',str(BASE.parents[1]/'gate_fixtures/secret_gate_cases.py')]
            seconds=FIXTURE_SECONDS
        else:
            command=[sys.executable,'-I','-B',str(BASE/'gate.py'),'--repo',str(Path.cwd()),'--revision',revision]
            seconds=SCAN_SECONDS
        proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=env,preexec_fn=process_limits,start_new_session=True)
        deadline=time.monotonic()+seconds
        with selectors.DefaultSelector() as sel:
            sel.register(proc.stdout,selectors.EVENT_READ)
            while sel.get_map():
                require(time.monotonic()<deadline,'whole-job-timeout')
                for key,_ in sel.select(min(.1,max(0,deadline-time.monotonic()))):
                    b=os.read(key.fileobj.fileno(),65536)
                    if not b: sel.unregister(key.fileobj)
                    else:
                        output.extend(b); require(len(output)<=OUTPUT_LIMIT,'output-limit')
            code=proc.wait(timeout=max(.001,deadline-time.monotonic()))
        if mode=='fixtures':
            require(code==0 and not output.strip(),'fixtures-failed')
            return {'status':'clean','stage':'synthetic-fixtures'}
        require(code in (0,1,2),'worker-failed')
        result=json.loads(output)
        require(isinstance(result,dict) and result.get('status') in ('clean','findings','incomplete'),'worker-report-invalid')
        require(code=={'clean':0,'findings':1,'incomplete':2}[result['status']],'worker-status-mismatch')
        if result['status']!='incomplete':
            require(result.get('revision')==revision and result.get('revision_type')=='commit','exact-event-commit-required')
        return result
    finally:
        if proc is not None:
            if proc.poll() is None: proc.kill()
            proc.wait(); proc.stdout.close()
        try: reap_descendants()
        finally: shutil.rmtree(directory)

def main():
    try:
        process_limits()
        require(len(sys.argv)==2 and sys.argv[1] in ('fixtures','scan'),'mode-required')
        revision=public_event()
        def cancel(*_): raise Failure('cancelled')
        signal.signal(signal.SIGTERM,cancel); signal.signal(signal.SIGINT,cancel)
        result=supervise(sys.argv[1], revision)
    except Failure as e: result={'status':'incomplete','errors':[{'code':str(e)}]}
    except Exception: result={'status':'incomplete','errors':[{'code':'runner-incomplete'}]}
    print(json.dumps(result,sort_keys=True))
    return {'clean':0,'findings':1,'incomplete':2}[result['status']]
if __name__=='__main__': sys.exit(main())
