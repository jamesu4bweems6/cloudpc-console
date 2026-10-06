"""Web console for the existing own-account protocol client."""
from __future__ import annotations
import argparse,datetime as dt,ipaddress,json,os,pathlib,secrets,signal,subprocess,sys,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit

HERE=pathlib.Path(__file__).resolve().parent
PROTOCOL=HERE.parent
sys.path.insert(0,str(PROTOCOL))
import cloudpc_protocol as p

TZ=dt.timezone(dt.timedelta(hours=8))
def now():return dt.datetime.now(TZ).isoformat()
def mask(value):
    value=str(value or '')
    return value[:3]+'••••'+value[-4:] if len(value)>7 else ('已配置' if value else '')

RESULT_FIELDS=('success','desktopProtocolConnected','gatewayAuthenticated','desktopChannelAuthenticated',
 'mainInitReceived','channelsListReceived','controlSessionCompleted','controlHoldSeconds',
 'connectedReportAccepted','disconnectedReportAccepted','ticketRefreshAccepted','startedAt','finishedAt','errorCode','errorType',
 'diagnosticCode','failedStage','sessionRecoveryAttempted','sessionRecovered','authenticationRequired')
def safe_result(value):
    result={k:value[k] for k in RESULT_FIELDS if k in value}
    if not value.get('success'):result['errorHint']=p.connection_failure_message(result)
    return result
def safe_machine(value):
    return {k:value.get(k) for k in ('machineId','machineName','machineStatus','originCompanyCode','resourceType','instanceId','resourcePoolUid')}

class Console:
    def __init__(self,start_scheduler=True):
        self.data_dir=pathlib.Path(os.environ.get('CLOUDPC_DATA_DIR',str(PROTOCOL))).resolve()
        self.data_dir.mkdir(parents=True,exist_ok=True)
        if not (self.data_dir/'account.local.json').exists():p.init_config(self.data_dir/'account.local.json')
        p.ensure_gateway_pins(self.data_dir)
        self.stopping=False;self.job=None
        self.lock=threading.RLock();self.wake=threading.Event()
        self.csrf=secrets.token_urlsafe(32);self.busy=False;self.action='';self.events=[];self.sequence=0
        self.loop=False;self.next_run=None;self.interval=12;self.hold=15;self.pending=None;self.last_result=None
        self.session_file=self.data_dir/'live/sms-session.local.json'
        for file in ('live/web-session.local.json','live/sms-session.local.json','session.local.json','live/password-session.local.json'):
            if (self.data_dir/file).exists():self.session_file=self.data_dir/file;break
        self.config_file=self.data_dir/'account.local.json'
        self.settings_file=self.data_dir/'live/web-settings.local.json'
        if self.settings_file.exists():
            settings=p.load_json(self.settings_file)
            self.interval=max(1,min(24,int(settings.get('intervalHours',12))))
            self.hold=max(5,min(60,int(settings.get('holdSeconds',15))))
        self.machines=[];self.load_cache()
        self.event('控制台已就绪，周期连接未启动。')
        if start_scheduler:threading.Thread(target=self.scheduler,daemon=True).start()

    def load_cache(self):
        cfg=p.load_json(self.config_file)
        for name in ('live/web-devices.local.json','live/sms-devices.local.json','devices.local.json'):
            file=self.data_dir/name
            if file.exists():
                try:self.machines=[safe_machine(m) for m in p.load_json(file)['body']['machineList']]
                except (KeyError,TypeError,ValueError):continue
                break
        self.target=cfg.get('target',{})
        results=sorted((self.data_dir/'live').glob('*-connect-once/result.local.json'))
        if results:self.last_result=safe_result(p.load_json(results[-1]))

    def event(self,message,level='info'):
        with self.lock:
            self.sequence+=1;self.events.append({'id':self.sequence,'at':now(),'message':message,'level':level})
            self.events=self.events[-120:]

    def history(self):
        values=[]
        for file in sorted((self.data_dir/'live').glob('*-connect-once/result.local.json'),reverse=True)[:8]:
            try:values.append(safe_result(p.load_json(file)))
            except (ValueError,OSError):continue
        return values

    def state(self):
        with self.lock:
            cfg=p.load_json(self.config_file);auth=cfg.get('auth',{})
            session=p.load_json(self.session_file) if self.session_file.exists() else {}
            return {'csrf':self.csrf,'busy':self.busy,'action':self.action,'loopEnabled':self.loop,
                    'nextRunAt':dt.datetime.fromtimestamp(self.next_run,TZ).isoformat() if self.next_run else None,
                    'intervalHours':self.interval,'holdSeconds':self.hold,'pending':self.pending,
                    'sessionAvailable':bool(session.get('accessTicket')) and not session.get('authRequired'),
                    'authenticationRequired':bool(session.get('authRequired')),
                    'sessionAt':session.get('tokenRefreshedAt') or session.get('loggedInAt'),
                    'auth':{'mobileHint':mask(auth.get('mobile')),'usernameConfigured':bool(auth.get('username')),
                            'passwordConfigured':bool(auth.get('password'))},
                    'machines':self.machines,'targetId':cfg.get('target',{}).get('machineId'),
                    'events':list(self.events),'lastResult':self.last_result,'history':self.history(),
                    'expiryRenewalVerified':False}

    def settings(self,data):
        interval=int(data.get('intervalHours',self.interval));hold=int(data.get('holdSeconds',self.hold))
        if not 1<=interval<=24 or not 5<=hold<=60:raise ValueError('连接间隔或保持时间超出范围')
        with self.lock:
            if self.busy or self.loop:raise ValueError('请等待当前操作完成并停止周期连接后修改设置')
            cfg=p.load_json(self.config_file)
            for key in ('mobile','username','password','selected_username'):
                value=data.get(key)
                if isinstance(value,str) and value:
                    if len(value)>256:raise ValueError('输入过长')
                    cfg['auth'][key]=value
            target=data.get('targetId')
            if target and target!=cfg.get('target',{}).get('machineId'):
                matches=[m for m in self.machines if m['machineId']==target and m['originCompanyCode']=='ZTE']
                if len(matches)!=1:raise ValueError('请选择本人列表中的 ZTE 云电脑')
                cfg['target']={k:matches[0].get(k) or '' for k in ('machineId','machineName','instanceId','resourcePoolUid')}
            p.save_json(self.config_file,cfg)
            self.interval=interval;self.hold=hold
            p.save_json(self.settings_file,{'intervalHours':interval,'holdSeconds':hold})
            self.event('本地配置已保存。')

    def start_job(self,action,data=None):
        data=data or {}
        with self.lock:
            if self.busy:raise ValueError('已有操作正在进行，请等待完成')
            if self.loop and action not in ('connect',):raise ValueError('请先停止周期连接再执行登录或刷新')
            if action=='sms-send' and getattr(self,'sms_at',0)+60>time.time():raise ValueError('请等待60秒再发送验证码')
            if action=='sms-send':self.sms_at=time.time()
            if self.stopping:raise ValueError('服务正在停止')
            self.busy=True;self.action=action
            self.event({'connect':'开始单次桌面连接。','devices':'正在刷新云电脑状态。','password':'正在验证账号密码。',
                        'sms-send':'正在请求登录验证码。','sms-login':'正在验证登录验证码。','challenge':'正在完成设备验证。'}[action])
            self.job=threading.Thread(target=self.worker,args=(action,data),daemon=True)
            self.job.start()

    def client(self):
        cfg=p.load_json(self.config_file)
        state=p.load_json(self.session_file) if self.session_file.exists() else {}
        audit=self.data_dir/'live'/('web-'+dt.datetime.now(TZ).strftime('%Y%m%d-%H%M%S-%f'))
        return p.Client(p.load_json(PROTOCOL/'sample-profile.json'),cfg,state,audit_dir=audit)

    def finish_login(self,client,response):
        code=str(response.get('errorCode'))
        if code in ('30002009','30002060'):
            auth=client.config['auth'];mobile=auth.get('mobile')
            if not mobile:raise p.ProtocolError('请先配置完整绑定手机号')
            kind='trust' if code=='30002009' else 'twoFactorAuth'
            self.challenge=response.get('body') or {};self.pending=kind
            self.challenge_auth={k:auth.get(k) for k in ('mobile','username','password')}
            self.challenge_at=time.time()
            client.send_sms(mobile,kind)
            self.event('设备验证短信已发送，请填写最新验证码。','pending')
            return
        client.finish_login(response,selected_username=client.config['auth'].get('selected_username'))
        self.session_file=self.data_dir/'live/web-session.local.json'
        p.save_json(self.session_file,client.state);self.pending=None
        self.challenge=None;self.challenge_auth=None
        self.event('登录与票据交换成功。','success')

    def worker(self,action,data):
        client=None
        try:
            if action=='connect':self.connect()
            else:
                client=self.client();auth=client.config['auth']
                if action=='devices':
                    response=client.prepare_session(client.devices,on_recovery=self.recovery_event)
                    p.save_json(self.session_file,client.state)
                    p.save_json(self.data_dir/'live/web-devices.local.json',response)
                    self.machines=[safe_machine(m) for m in response['body']['machineList']]
                    self.event('云电脑状态已更新。','success')
                elif action=='password':
                    if not auth.get('username') or not auth.get('password'):raise p.ProtocolError('请先保存账号和密码')
                    self.finish_login(client,client.verify_password(auth['username'],auth['password']))
                elif action=='sms-send':
                    if not auth.get('mobile'):raise p.ProtocolError('请先保存手机号')
                    client.send_sms(auth['mobile']);self.event('登录验证码已发送。','success')
                elif action in ('sms-login','challenge'):
                    code=str(data.get('code','')).strip()
                    if not code or len(code)>12:raise p.ProtocolError('请输入有效验证码')
                    if action=='sms-login':response=client.verify_sms(auth['mobile'],code)
                    else:
                        if not self.pending or time.time()-self.challenge_at>600:raise p.ProtocolError('设备验证已过期，请重新密码登录')
                        a=self.challenge_auth
                        response=client.trust_device(self.challenge,a['mobile'],code,a['username']) if self.pending=='trust' else client.verify_two_factor(self.challenge,a['username'],a['password'],a['mobile'],code)
                    self.finish_login(client,response)
        except Exception as exc:
            code=exc.code if isinstance(exc,(p.BusinessError,p.AuthenticationRequired)) else None
            labels={'401':'会话已失效，请重新登录。','30001004':'账号或密码验证失败，请检查本地配置。',
                    '10002034':'需要选择企业账号，请填写企业用户名后再登录。'}
            message=labels.get(code,'操作未完成：'+type(exc).__name__+(('（业务码 '+code+'）') if code else ''))
            if isinstance(exc,p.ProtocolError) and not isinstance(exc,p.BusinessError):message=str(exc)[:150]
            if action=='devices' and client is not None:
                if code=='401':client.state['authRequired']=True
                p.save_json(self.session_file,client.state)
            self.event(message,'error')
            if action=='connect':
                with self.lock:self.loop=False;self.next_run=None
                self.event('周期连接已停止。','error')
        finally:
            with self.lock:
                self.busy=False;self.action=''
                if self.loop:self.next_run=time.time()+self.interval*3600
            self.wake.set()

    def recovery_event(self,status):
        self.event({'started':'登录票据已失效，正在尝试一次密码续登。',
                    'success':'密码续登成功，已更新本地会话。'}[status],
                   'success' if status=='success' else 'info')

    def connect(self):
        cmd=[sys.executable,'-X','utf8',str(PROTOCOL/'connect_once.py'),'--config',str(self.config_file),'--session',str(self.session_file),
             '--hold-seconds',str(self.hold)]
        env=os.environ.copy();env['CLOUDPC_DATA_DIR']=str(self.data_dir)
        proc=subprocess.Popen(cmd,cwd=PROTOCOL,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8')
        result=None
        labels={'login/verifyAccessTicket':'票据交换请求已返回。','login/recordDeviceInfo':'会话注册请求已返回。',
                'session/machineConnect':'桌面连接上报请求已返回。'}
        for line in proc.stdout:
            try:value=json.loads(line)
            except (ValueError,TypeError):continue
            if value.get('stage')=='connect-once':result=value
            elif value.get('stage')=='session-recovery':
                if value.get('status') in ('started','success'):self.recovery_event(value['status'])
            elif value.get('path'):
                path=value['path'].removeprefix(p.PREFIX)
                if path in labels:self.event(labels[path])
                # HTTP status only describes transport; wait for decoded final result.
        proc.wait()
        if result:self.last_result=safe_result(result)
        if proc.returncode or not result or not result.get('success'):
            raise p.ProtocolError('连接未完成：'+p.connection_failure_message(result))
        self.event('桌面认证成功，已保持 '+str(result.get('controlHoldSeconds',self.hold))+' 秒并完成断开上报。','success')

    def set_loop(self,enabled):
        with self.lock:
            if enabled:
                if self.stopping:raise ValueError('服务正在停止')
                if self.busy:raise ValueError('请等待当前操作完成')
                if not self.session_file.exists() or p.load_json(self.session_file).get('authRequired'):raise ValueError('请先重新登录')
                self.loop=True;self.next_run=time.time()
                self.event('周期连接已开启，将立即执行首次连接。','success')
            else:
                self.loop=False;self.next_run=None
                self.event('周期连接已停止；正在进行的连接会正常完成并清理。')
        self.wake.set()

    def scheduler(self):
        while not self.stopping:
            self.wake.wait(1);self.wake.clear()
            with self.lock:
                due=not self.stopping and self.loop and not self.busy and self.next_run is not None and time.time()>=self.next_run
                if due:self.start_job('connect')

    def close(self):
        with self.lock:self.stopping=True;self.loop=False;self.next_run=None;job=self.job
        self.wake.set()
        if job:job.join(timeout=85)

def allowed_origins(port,extra=()):
    origins={f'http://127.0.0.1:{port}',f'http://localhost:{port}'}
    for value in extra:
        parsed=urlsplit(value)
        if (parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment or '*' in value):
            raise ValueError('公开访问地址必须是完整的 http/https 来源，不能包含路径或通配符')
        parsed.port  # Reject invalid port syntax.
        origins.add(value)
    return origins

def public_ip_host(host,port):
    if not host or port is None:return False
    try:
        parsed=urlsplit('http://'+host)
        if (parsed.netloc!=host or parsed.path or parsed.query or parsed.fragment
            or parsed.username or parsed.password or parsed.port!=port or '%' in host):return False
        ipaddress.ip_address(parsed.hostname)
        return True
    except (ValueError,TypeError):return False

def make_handler(console,port,extra_origins=(),public_port=None):
    origins=allowed_origins(port,extra_origins)
    if public_port is not None:origins.update(allowed_origins(public_port))
    hosts={urlsplit(origin).netloc for origin in origins}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def allowed(self):
            host=self.headers.get('Host')
            return host in hosts or public_ip_host(host,public_port)
        def reply(self,code,value,content_type='application/json; charset=utf-8'):
            data=json.dumps(value,ensure_ascii=False).encode() if isinstance(value,(dict,list)) else value
            self.send_response(code)
            self.send_header('Content-Type',content_type);self.send_header('Content-Length',str(len(data)))
            self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
            self.end_headers();self.wfile.write(data)
        def do_GET(self):
            if not self.allowed():return self.reply(403,{'error':'访问地址未配置或端口不匹配'})
            path=urlsplit(self.path).path
            if path=='/healthz':return self.reply(200,{'ok':True})
            if path=='/api/state':return self.reply(200,console.state())
            assets={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','application/javascript; charset=utf-8'),'/style.css':('style.css','text/css; charset=utf-8')}
            if path not in assets:return self.reply(404,{'error':'未找到'})
            name,mime=assets[path];self.reply(200,(HERE/name).read_bytes(),mime)
        def do_POST(self):
            if not self.allowed():return self.reply(403,{'error':'访问地址未配置或端口不匹配'})
            origin=self.headers.get('Origin')
            host=self.headers.get('Host')
            same_ip_origin=public_ip_host(host,public_port) and origin in (f'http://{host}',f'https://{host}')
            if (origin not in origins and not same_ip_origin) or self.headers.get('X-CSRF-Token')!=console.csrf:
                return self.reply(403,{'error':'请求来源或校验不匹配，请重新打开页面'})
            if self.headers.get('Content-Type','').split(';')[0]!='application/json':return self.reply(415,{'error':'需要JSON请求'})
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=8192:raise ValueError('请求大小无效')
                value=json.loads(self.rfile.read(length))
                if not isinstance(value,dict):raise ValueError('请求无效')
                action=urlsplit(self.path).path.removeprefix('/api/')
                if action=='settings':console.settings(value)
                elif action=='loop-start':console.set_loop(True)
                elif action=='loop-stop':console.set_loop(False)
                elif action in ('connect','devices','password','sms-send','sms-login','challenge'):console.start_job(action,value)
                else:return self.reply(404,{'error':'未知操作'})
                self.reply(200,{'accepted':True})
            except (ValueError,KeyError) as exc:self.reply(400,{'error':str(exc)[:150]})
    return Handler

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--port',type=int,default=8765)
    ap.add_argument('--bind',choices=('127.0.0.1','0.0.0.0'),default='127.0.0.1')
    ap.add_argument('--public-origin',action='append',default=[])
    ap.add_argument('--public-port',type=int,default=os.environ.get('CLOUDPC_PUBLIC_PORT'),help='允许通过IP访问的宿主机端口；默认不启用')
    args=ap.parse_args()
    if not 1024<=args.port<=65535:ap.error('端口必须在1024..65535')
    if args.public_port is not None and not 1<=args.public_port<=65535:ap.error('公开端口必须在1..65535')
    extra=args.public_origin+[x.strip() for x in os.environ.get('CLOUDPC_PUBLIC_ORIGINS','').split(',') if x.strip()]
    try:allowed_origins(args.port,extra)
    except ValueError as exc:ap.error(str(exc))
    console=Console();server=ThreadingHTTPServer((args.bind,args.port),make_handler(console,args.port,extra,args.public_port))
    def stop(signum,frame):
        with console.lock:console.stopping=True;console.loop=False;console.next_run=None
        console.wake.set()
        threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,stop)
    print(f'本地控制台: http://127.0.0.1:{args.port}',flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:console.close();server.server_close()

if __name__=='__main__':main()
