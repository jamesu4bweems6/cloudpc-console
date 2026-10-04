"""Run one explicit validation stage, keeping credentials/responses out of stdout."""
import argparse
import datetime as dt
import json
import pathlib
import re
import sys
import time
from urllib.parse import urlsplit
import requests
import cloudpc_protocol as p

ROOT = p.DATA_DIR / 'live'

def timestamp():
    return dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime('%Y%m%d-%H%M%S-%f')

class LocalAuditTransport:
    def __init__(self, directory):
        self.session = requests.Session()
        self.directory = directory
        self.trace = []
    def post(self, url, **kwargs):
        start = time.monotonic()
        response = self.session.post(url, **kwargs)
        ident = len(self.trace)+1
        (self.directory/f'{ident:03d}-response.bin').write_bytes(response.content)
        item = {'path':urlsplit(url).path, 'httpStatus':response.status_code,
            'contentType':response.headers.get('Content-Type'), 'responseBytes':len(response.content),
            'elapsedMs':round((time.monotonic()-start)*1000)}
        try:
            raw = response.json()
            item['outerKeys'] = sorted(raw) if isinstance(raw,dict) else type(raw).__name__
        except ValueError:
            item['outerKeys'] = 'not-json'
        self.trace.append(item)
        p.save_json(self.directory/'transport.local.json',self.trace)
        print(json.dumps(item,ensure_ascii=False))
        return response

def safe_message(response, auth):
    value = str(response.get('errorMessage') or response.get('message') or '')
    for secret in auth.values():
        if isinstance(secret,str) and secret:
            value = value.replace(secret,'[REDACTED]')
    value = re.sub(r'\b1[3-9]\d{9}\b','[PHONE]',value)
    value = re.sub(r'\b[A-Za-z0-9_+/=-]{32,}\b','[LONG-VALUE]',value)
    return value[:200]

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('stage',choices=['password','sms-send','sms-verify','resume-password','devices','snapshot','probe'])
    ap.add_argument('--session-name',default='password')
    ap.add_argument('--config',type=pathlib.Path,default=p.DATA_DIR/'account.local.json')
    args = ap.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+',args.session_name):
        raise p.ProtocolError('Invalid local session name')
    config = p.load_json(args.config)
    auth = config['auth']
    directory = ROOT/(timestamp()+'-'+args.stage)
    directory.mkdir(parents=True)
    state_file = ROOT/(args.session_name+'-session.local.json')
    state = p.load_json(state_file) if state_file.exists() else {}
    if args.stage in ('password','sms-verify'):
        state = {}
    transport = LocalAuditTransport(directory)
    client = p.Client(p.load_json(p.HERE/'sample-profile.json'),config,state,
                      transport=transport,audit_dir=directory)
    pending_file = ROOT/(args.session_name+'-pending.local.json')
    result = {'stage':args.stage,'startedAt':dt.datetime.now(dt.timezone.utc).isoformat(),'success':False}
    def finish(response):
        code = str(response.get('errorCode'))
        if code in ('30002009','30002060'):
            challenge = response.get('body') or {}
            mobile = auth.get('mobile') or challenge.get('mobile')
            if not mobile or '*' in mobile:
                raise p.ProtocolError('需要配置完整绑定手机号')
            code_type = 'trust' if code=='30002009' else 'twoFactorAuth'
            # Preserve challenge before requesting SMS, without copying credentials.
            p.save_json(pending_file,{'kind':code_type,'challenge':challenge,'requestedAt':timestamp()})
            client.send_sms(mobile,code_type)
            result.update(pending=code_type, smsRequested=True)
            print('登录需要短信验证；已发送一次。请将验证码填入配置 auth.verification_code 后继续。')
            return
        client.finish_login(response,selected_username=auth.get('selected_username'))
        result.update(success=True,loginComplete=True)
        print('登录和票据交换完成。')
    try:
        if args.stage=='password':
            if not auth.get('username') or not auth.get('password'):
                raise p.ProtocolError('本地账号密码未填写')
            finish(client.verify_password(auth['username'],auth['password']))
        elif args.stage=='sms-send':
            client.send_sms(auth['mobile'])
            result.update(success=True,smsRequested=True)
            print('登录短信发送请求已接受；请本地填写 auth.verification_code。')
        elif args.stage=='sms-verify':
            code = auth.get('verification_code')
            if not code:
                raise p.ProtocolError('请本地填写 auth.verification_code')
            finish(client.verify_sms(auth['mobile'],str(code)))
        elif args.stage=='resume-password':
            pending = p.load_json(pending_file)
            code = auth.get('verification_code')
            if not code:
                raise p.ProtocolError('请本地填写 auth.verification_code')
            if pending['kind']=='trust':
                r = client.trust_device(pending['challenge'],auth['mobile'],str(code),auth['username'])
            else:
                r = client.verify_two_factor(pending['challenge'],auth['username'],auth['password'],auth['mobile'],str(code))
            finish(r)
        elif args.stage=='devices':
            response = client.devices()
            p.save_json(ROOT/(args.session_name+'-devices.local.json'),response)
            body = response.get('body')
            result.update(success=True, bodyType=type(body).__name__,
                          bodyKeys=sorted(body) if isinstance(body,dict) else [])
            print(json.dumps({k:result[k] for k in ('success','bodyType','bodyKeys')},ensure_ascii=False))
        elif args.stage=='snapshot':
            response = client.snapshot(config['target'])
            p.save_json(directory/'snapshot.local.json',response)
            result['success']=True
        elif args.stage=='probe':
            result.update(client.report_probe(config['target']),success=True)
    except p.BusinessError as exc:
        p.save_json(directory/'business-error.local.json',exc.response)
        result.update(errorCode=exc.code,message=safe_message(exc.response,auth))
        print(json.dumps({'errorCode':exc.code,'message':result['message']},ensure_ascii=False))
    except (p.ProtocolError,requests.RequestException) as exc:
        # Do not echo exception URLs (they contain signing parameters).
        result['errorType']=type(exc).__name__
        if isinstance(exc,p.ProtocolError):
            print(str(exc))
        else:
            print('请求未完成；已记录错误类型，没有自动重试。')
    finally:
        if client.state.get('accessToken'):
            p.save_json(state_file,client.state)
        p.save_json(directory/'result.local.json',result)
        print('本地结果目录: '+str(directory))
    return 0 if result['success'] or result.get('pending') else 1

if __name__=='__main__':
    sys.exit(main())
