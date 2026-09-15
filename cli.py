"""Headless worker. Dry-run by default; suitable for an external scheduler."""
import argparse
import getpass
import json
import os
import shutil
import sys
from pathlib import Path
from engine import Job, Settings, SafetyError


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--org',required=True)
    p.add_argument('--instance',default='d')
    p.add_argument('--user-instance',default='D')
    p.add_argument('--csv',type=Path)
    p.add_argument('--run-dir',required=True,type=Path)
    p.add_argument('--mode',choices=['Selective','Bulk'],default='Selective')
    p.add_argument('--verification',choices=['Auto','Selective','Bulk'],default='Auto')
    p.add_argument('--workers',type=int,default=6)
    p.add_argument('--page-size',type=int,default=1000)
    p.add_argument('--batch-size',type=int,default=256)
    p.add_argument('--recover',action='store_true')
    p.add_argument('--execute',action='store_true')
    p.add_argument('--confirm-count',type=int,help='Exact expected remaining target count; required to execute')
    args=p.parse_args()
    if args.execute and (args.confirm_count is None or args.confirm_count<=0):
        p.error('--execute requires a positive --confirm-count')
    token=os.environ.get('TL_AUTHORIZATION')
    if not token and (sys.stdin is None or not sys.stdin.isatty()):
        p.error('Set TL_AUTHORIZATION for unattended execution.')
    token=token or getpass.getpass('Authorization: ')
    cfg=Settings(args.org.strip().lower(),token,args.instance,args.user_instance,args.workers,args.mode,
                 args.page_size,60,args.batch_size,args.verification)
    try:
        if args.recover:
            job=Job.restore(cfg,args.run_dir)
            job.start(recover=True)
        else:
            if not args.csv or args.run_dir.exists():
                raise SafetyError('Provide --csv and a NEW --run-dir, or use --recover on an existing run.')
            job=Job(cfg,args.run_dir)
            shutil.copyfile(args.csv,args.run_dir/'input.csv')
            job.start()
        def follow():
            while job.active:
                job.thread.join(5)
                print(json.dumps(job.snapshot()),flush=True)
        follow()
        if job.phase!='Ready':
            return 1
        if args.execute:
            if job.snapshot().get('planned')!=args.confirm_count:
                raise SafetyError('Exact target count differs from authorized count. No deletions sent.')
            job.start(execute=True)
            follow()
            return 0 if job.phase=='Complete' else 1
        return 0
    except KeyboardInterrupt:
        if 'job' in locals() and job.active:
            job.stop.set()
            print('Stopping submissions; waiting for in-flight reconciliation.',flush=True)
            job.thread.join()
        return 130
    except SafetyError as e:
        print(str(e))
        return 1


if __name__=='__main__':
    raise SystemExit(main())
