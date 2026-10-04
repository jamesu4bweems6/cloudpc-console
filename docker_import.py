"""Import this user's local JSON state into the stopped Compose data volume."""
import argparse,json,pathlib,shutil,subprocess,sys

HERE=pathlib.Path(__file__).resolve().parent
FILES=('account.local.json','session.local.json','devices.local.json',
       'live/web-session.local.json','live/sms-session.local.json',
       'live/password-session.local.json','live/web-devices.local.json',
       'live/sms-devices.local.json','live/web-settings.local.json',
       'live/zte-cag-pin.local.json','live/zte-ice-pin.local.json')

# Writes as the service UID, with atomic replacement and private file modes.
IMPORT_CODE='''import json,os,pathlib,sys
import cloudpc_protocol as p
values=json.load(sys.stdin)
for name,value in values.items():
    dest=p.DATA_DIR/name
    if not dest.resolve().is_relative_to(p.DATA_DIR):raise ValueError('Invalid destination')
    p.save_json(dest,value)
    os.chmod(dest,0o600)
print('Imported JSON files: '+str(len(values)))
'''

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source',type=pathlib.Path,default=HERE)
    args=ap.parse_args()
    if not shutil.which('docker'):ap.error('未安装 Docker 或 docker 未加入 PATH')
    def compose(*cmd,**kwargs):
        return subprocess.run(['docker','compose',*cmd],cwd=HERE,check=True,**kwargs)
    running=compose('ps','--status','running','--quiet',capture_output=True,text=True)
    if running.stdout.strip():ap.error('请先在网页停止周期连接并等待任务完成，再执行 docker compose stop')
    source=args.source.resolve()
    values={name:json.loads((source/name).read_text(encoding='utf-8')) for name in FILES if (source/name).is_file()}
    if 'account.local.json' not in values:ap.error('源目录缺少 account.local.json')
    compose('create','--build')
    compose('run','--rm','--no-deps','-T','--entrypoint','python','cloudpc','-c',IMPORT_CODE,
            input=json.dumps(values,ensure_ascii=False).encode('utf-8'))
    print('迁移完成。执行 docker compose up -d 启动网页。')

if __name__=='__main__':
    try:main()
    except (OSError,ValueError,subprocess.CalledProcessError) as exc:
        print('迁移未完成：'+type(exc).__name__,file=sys.stderr);sys.exit(1)
