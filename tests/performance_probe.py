"""Optional local-only scaling benchmark. No network requests or real credentials."""
import csv
import json
from pathlib import Path
import tempfile
import time
from contextlib import closing
from dataclasses import replace
from engine import Job, Settings, connect, initialize, import_csv

ORG='11111111-1111-1111-1111-111111111111'
APP='22222222-2222-2222-2222-222222222222'


class GeneratedClient:
    def __init__(self,cfg,size):
        self.cfg=cfg
        self.size=size
        self.removed=set()
    def application(self,appid,os):
        assert appid==APP and os==2
        return dict(applicationId=APP,organizationId=ORG,osType=2,name='Generated local fixture')
    def files(self,appid,search='',cancelled=lambda:False):
        assert appid==APP
        indices=[int(search,16)] if search else range(self.size)
        for i in indices:
            if cancelled():
                from engine import Cancelled
                raise Cancelled()
            if 0<=i<self.size and i not in self.removed:
                yield dict(applicationId=APP,applicationFileId=str(i),hash=f'{i:064X}',isHashOnly=True)
    def delete(self,body):
        assert body['applicationId']==APP
        self.removed.add(int(body['applicationFileId']))
        return True,'SIMULATED'
    def close(self):pass


def csv_file(path,count):
    with path.open('w',newline='') as f:
        w=csv.writer(f);w.writerow(['ApplicationId','Hash','OsType'])
        w.writerows((APP,f'{i:064X}',2) for i in range(count))


def main():
    results={}
    with tempfile.TemporaryDirectory(prefix='tl-local-scale-') as tmp:
        root=Path(tmp)
        path=root/'million.csv'
        csv_file(path,1000000)
        with closing(connect(root/'import.sqlite3')) as db:
            initialize(db)
            start=time.perf_counter()
            count,duplicates=import_csv(db,path)
            assert count==1000000 and duplicates==0
            results['million_csv_import_seconds']=round(time.perf_counter()-start,2)
        print(json.dumps(results),flush=True)
        cfg=Settings(ORG,'fake',workers=6,mode='Bulk',page_size=10000)
        directory=root/'scan';directory.mkdir()
        csv_file(directory/'input.csv',1000)
        job=Job(cfg,directory,lambda c:GeneratedClient(c,1000000))
        job.start();job.thread.join()
        assert job.phase=='Ready',job.message
        assert job.snapshot()['planned']==1000
        results['million_application_scan']=job.snapshot()
        print(json.dumps(results),flush=True)
        results['batch_comparison']=[]
        for batch in (1,256):
            directory=root/f'batch-{batch}';directory.mkdir()
            csv_file(directory/'input.csv',2000)
            job=Job(replace(cfg,batch_size=batch),directory,lambda c:GeneratedClient(c,2000))
            job.start();job.thread.join()
            assert job.phase=='Ready',job.message
            job.start(execute=True);job.thread.join()
            assert job.phase=='Complete',job.message
            results['batch_comparison'].append(dict(batch=batch,**job.snapshot()))
        print(json.dumps(results,indent=2),flush=True)
        output=Path(__file__).resolve().parents[1]/'runs'/'local-performance.json'
        output.parent.mkdir(exist_ok=True)
        output.write_text(json.dumps(results,indent=2))


if __name__=='__main__':main()
