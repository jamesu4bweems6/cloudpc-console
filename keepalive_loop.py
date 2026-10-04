"""Run the verified connect-once flow periodically while this process runs.

This is a renewal candidate; automatic shutdown prevention is not yet verified.
No scheduled task is installed. A failed connection stops the loop.
"""
import argparse,pathlib,subprocess,sys,time,datetime as dt
import cloudpc_protocol as p

def main():
    here=pathlib.Path(__file__).resolve().parent
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--session',type=pathlib.Path,default=p.DATA_DIR/'session.local.json')
    ap.add_argument('--config',type=pathlib.Path,default=p.DATA_DIR/'account.local.json')
    ap.add_argument('--interval-hours',type=int,default=12,choices=range(1,13))
    args=ap.parse_args()
    while True:
        result=subprocess.run([sys.executable,'-X','utf8',str(here/'connect_once.py'),
                               '--session',str(args.session.resolve()),'--config',str(args.config.resolve())])
        if result.returncode:
            print('连接失败，已停止循环；请检查本地结果，必要时重新登录。',flush=True)
            return result.returncode
        print(f'下一次连接约在 {dt.datetime.now()+dt.timedelta(hours=args.interval_hours):%Y-%m-%d %H:%M:%S}；Ctrl+C 停止。',flush=True)
        # Short interruptible local sleeps; no server traffic during this wait.
        deadline=time.monotonic()+args.interval_hours*3600
        while time.monotonic()<deadline:time.sleep(min(30,deadline-time.monotonic()))

if __name__=='__main__':
    try:sys.exit(main())
    except KeyboardInterrupt:print('循环已停止。');sys.exit(0)
