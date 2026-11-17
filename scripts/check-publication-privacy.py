#!/usr/bin/env python3
"""Check an explicit public source/release tree against a local private deny policy."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

PRIVATE_KEY=re.compile(rb'(?m)^-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]{32,}')
FORBIDDEN_SOURCE=('build/','results/','dist/','.aws/','.codex/','.agents/','.env','config.local.')

def check_files(paths,patterns,nested=True):
    hits=[];count=0;byte_count=0
    def scan(name,stream,size):
        nonlocal count,byte_count
        count+=1;byte_count+=size;tail=b'';found=set()
        for chunk in iter(lambda:stream.read(1<<20),b''):
            data=tail+chunk
            found.update(label for label,needle in patterns if needle and needle in data)
            if PRIVATE_KEY.search(data):found.add('private_key_material')
            tail=data[-16384:]
        if found:hits.append(dict(file=name,labels=sorted(found)))
    for name,path in paths:
        if path.is_symlink() or not path.is_file():
            hits.append(dict(file=name,labels=['linked_or_special_public_input']));continue
        scan(name,io.BytesIO(name.encode()),len(name.encode()))
        before=path.stat()
        with path.open('rb') as stream:scan(name,stream,before.st_size)
        after=path.stat()
        if (before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns):
            hits.append(dict(file=name,labels=['changed_during_scan']))
        if nested and name.endswith(('.tar.gz','.tgz')):
            try:
                with tarfile.open(path,'r:gz') as archive:
                    total=0
                    for member in archive:
                        if member.isfile():
                            total+=member.size
                            if total>2<<30:raise ValueError('nested archive exceeds privacy scan bound')
                            scan(name+'!/'+member.name,archive.extractfile(member),member.size)
                        elif not member.isdir():hits.append(dict(file=name+'!/'+member.name,labels=['nested_special_file']))
            except tarfile.TarError:hits.append(dict(file=name,labels=['unreadable_nested_archive']))
    return dict(passed=not hits,files_and_nested_members_checked=count,bytes_checked=byte_count,hits=hits)

check_publication_paths=check_files

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree',type=Path,required=True)
    parser.add_argument('--private-policy',type=Path,required=True)
    parser.add_argument('--git',action='store_true')
    parser.add_argument('--require-fresh-history',action='store_true')
    parser.add_argument('--secret-fd',type=int,help='optional inherited descriptor; secret is never logged or stored')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();root=args.tree.resolve()
    policy=json.loads(args.private_policy.read_text())
    if policy.get('protocol')!='osv-private-publication-policy/v1':raise ValueError('unsupported private policy')
    patterns=[(label,value.encode()) for label,value in policy['deny_literals'].items()]
    if args.secret_fd is not None:
        secret=os.read(args.secret_fd,16384).rstrip(b'\r\n')
        if not secret:raise ValueError('empty private secret input')
        patterns.append(('session_secret',secret))
    if args.git:
        if args.require_fresh_history:
            count=int(subprocess.check_output(['git','-C',root,'rev-list','--count','HEAD'],text=True))
            if count!=1:raise ValueError('initial privacy-sanitized publication requires one clean root commit')
        names=subprocess.check_output(['git','-C',root,'ls-files','-z'],text=True).split('\0')
        names=[name for name in names if name]
        forbidden=[name for name in names if name.startswith(FORBIDDEN_SOURCE)]
    else:
        names=[str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() or p.is_symlink()]
        forbidden=[]
    result=check_files([(name,root/name) for name in names],patterns)
    result.update(protocol='osv-publication-privacy-check/v1',scope='tracked_source' if args.git else 'explicit_release_tree',
        local_private_policy_not_embedded=True,policy_rule_count=len(patterns),session_secret_checked=args.secret_fd is not None,
        forbidden_source_paths=forbidden)
    result['passed']=result['passed'] and not forbidden
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(passed=result['passed'],files_checked=result['files_and_nested_members_checked'],findings=len(result['hits'])+len(forbidden))))
    return 0 if result['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
