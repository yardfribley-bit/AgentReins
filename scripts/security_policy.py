#!/usr/bin/env python3
"""Initialize or validate the local AgentReins sensitive-data policy."""
import argparse,json,os
from pathlib import Path
parser=argparse.ArgumentParser()
parser.add_argument('--path',type=Path,default=Path.home()/'Library/Application Support/AgentReins/security-policy.json')
parser.add_argument('--init',action='store_true')
args=parser.parse_args()
if args.init:
    args.path.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(args.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:
        json.dump({'approvedModelHosts':[], 'rules':[{'name':'内部项目标记','kind':'keyword','value':'替换为需要检测的内部标记','enabled':False},{'name':'需要保护的密钥','kind':'secret','value':'替换为需要检测的敏感值','enabled':False}]},f,ensure_ascii=False,indent=2)
value=json.loads(args.path.read_text())
assert isinstance(value.get('rules'),list) and len(value['rules'])<=100
for rule in value['rules']:
    assert rule.get('kind') in ('keyword','secret')
    assert isinstance(rule.get('value'),str) and 3<=len(rule['value'])<=4096
assert isinstance(value.get('approvedModelHosts'),list)
assert all(isinstance(h,str) for h in value['approvedModelHosts'])
print('策略有效：',args.path,'；规则数量：',len(value['rules']))
