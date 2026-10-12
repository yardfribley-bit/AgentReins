import argparse,json,subprocess,time,statistics
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--pids',required=True);p.add_argument('--output',required=True);a=p.parse_args()
def cpu_seconds(value):
    total=0
    for part in value.split(':'):total=total*60+float(part)
    return total
samples=[]
for i in range(9):
    raw=subprocess.check_output(['ps','-p',a.pids,'-o','pid=,%cpu=,rss=,time=,comm='],text=True);apps={}
    for line in raw.splitlines():
        v=line.split(None,4);apps[Path(v[4]).name]={'pid':int(v[0]),'cpu':float(v[1]),'rssMB':round(int(v[2])/1024,1),'cpuSeconds':cpu_seconds(v[3])}
    samples.append({'at':time.time(),'apps':apps})
    if i<8:time.sleep(5)
elapsed=samples[-1]['at']-samples[0]['at'];result={'elapsed':elapsed,'samples':samples,'mean':{n:round(statistics.mean(s['apps'][n]['cpu'] for s in samples),1) for n in apps},'intervalCPU':{n:round(100*(samples[-1]['apps'][n]['cpuSeconds']-samples[0]['apps'][n]['cpuSeconds'])/elapsed,1) for n in apps}}
Path(a.output).write_text(json.dumps(result,indent=2));print(json.dumps({k:result[k] for k in ['elapsed','mean','intervalCPU']}))
