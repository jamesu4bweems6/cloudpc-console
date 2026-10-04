"""Offline checks of container runtime boundaries, without a Docker daemon."""
import contextlib,http.client,io,json,os,pathlib,subprocess,sys,tempfile,threading,unittest
from unittest.mock import Mock,patch
import server as w
import docker_import as migration

class ContainerRuntimeChecks(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.data=pathlib.Path(self.temp.name).resolve()/'data'
        self.env=patch.dict(os.environ,{'CLOUDPC_DATA_DIR':str(self.data)});self.env.start()
        self.console=w.Console(start_scheduler=False)

    def tearDown(self):
        self.console.close();self.env.stop();self.temp.cleanup()

    def test_first_start_and_restart_preserve_identity_and_settings(self):
        first=w.p.load_json(self.console.config_file)
        self.console.settings({'mobile':'13812345678','password':'PRIVATE','intervalHours':6})
        session=self.data/'live/web-session.local.json'
        w.p.save_json(session,{'accessTicket':'PRIVATE_TICKET'})
        restarted=w.Console(start_scheduler=False)
        try:
            self.assertEqual(w.p.load_json(restarted.config_file)['common']['deviceUid'],first['common']['deviceUid'])
            self.assertEqual(restarted.interval,6);self.assertEqual(restarted.session_file,session)
            self.assertTrue(restarted.state()['sessionAvailable']);self.assertFalse(restarted.loop)
            self.assertEqual(restarted.history(),[])
        finally:restarted.close()

    def test_console_bootstrap_pins_and_preserves_existing_override(self):
        for name in ('zte-cag-pin','zte-ice-pin'):
            self.assertEqual(w.p.load_json(self.data/'live'/(name+'.local.json')),
                             w.p.load_json(w.p.HERE/'gateway-pins'/(name+'.json')))
        override={'url':'https://192.0.2.99:443/cs/test','sha256':'f'*64}
        w.p.save_json(self.data/'live/zte-cag-pin.local.json',override)
        restarted=w.Console(start_scheduler=False)
        try:self.assertEqual(w.p.load_json(self.data/'live/zte-cag-pin.local.json'),override)
        finally:restarted.close()

    def test_protocol_process_reads_environment_data_directory(self):
        code="import json,cloudpc_protocol as p,live_validate as v;print(json.dumps([str(p.DATA_DIR),str(v.ROOT)]))"
        result=subprocess.run([sys.executable,'-X','utf8','-c',code],cwd=w.PROTOCOL,
                              capture_output=True,text=True,check=True)
        self.assertEqual(json.loads(result.stdout),[str(self.data),str(self.data/'live')])

    def test_connection_child_inherits_data_config_and_session(self):
        proc=Mock();proc.stdout=iter([json.dumps({'stage':'connect-once','success':True})]);proc.returncode=0
        with patch.object(w.subprocess,'Popen',return_value=proc) as spawn:self.console.connect()
        args,kwargs=spawn.call_args
        self.assertEqual(kwargs['env']['CLOUDPC_DATA_DIR'],str(self.data))
        cmd=args[0]
        self.assertEqual(cmd[cmd.index('--config')+1],str(self.data/'account.local.json'))
        self.assertEqual(cmd[cmd.index('--session')+1],str(self.console.session_file))
        self.assertEqual(kwargs['cwd'],w.PROTOCOL)

    def test_mapped_host_origin_health_and_csrf(self):
        server=w.ThreadingHTTPServer(('127.0.0.1',0),w.make_handler(self.console,0))
        port=server.server_address[1]
        external='http://localhost:18766'
        server.RequestHandlerClass=w.make_handler(self.console,port,[external])
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        def request(method,path,headers,body=None):
            conn=http.client.HTTPConnection('127.0.0.1',port)
            conn.request(method,path,headers=headers,body=body)
            response=conn.getresponse();status=response.status;data=response.read();conn.close()
            return status,data
        try:
            self.assertEqual(request('GET','/',{'Host':'localhost:18766'})[0],200)
            self.assertEqual(request('GET','/healthz',{'Host':f'127.0.0.1:{port}'}),(200,b'{"ok": true}'))
            headers={'Host':'localhost:18766','Origin':external,'Content-Type':'application/json','X-CSRF-Token':self.console.csrf}
            self.assertEqual(request('POST','/api/loop-stop',headers,'{}')[0],200)
            headers['Origin']='http://evil.example'
            self.assertEqual(request('POST','/api/loop-stop',headers,'{}')[0],403)
            headers['Origin']=external;headers['X-CSRF-Token']='wrong'
            self.assertEqual(request('POST','/api/loop-stop',headers,'{}')[0],403)
            self.assertEqual(request('GET','/api/state',{'Host':'localhost:18767'})[0],403)
        finally:server.shutdown();server.server_close();thread.join()

    def test_invalid_public_origins_rejected(self):
        for value in ('*','http://*.example','file:///tmp','http://user:secret@example.com','http://localhost:8000/path','http://localhost:bad'):
            with self.subTest(value=value),self.assertRaises(ValueError):w.allowed_origins(8765,[value])

    def test_remote_ip_and_custom_domain_keep_origin_and_csrf_checks(self):
        server=w.ThreadingHTTPServer(('127.0.0.1',0),w.make_handler(self.console,0))
        port=server.server_address[1]
        server.RequestHandlerClass=w.make_handler(self.console,port,['https://cloudpc.example.com'],8766)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        def request(method,path,host,origin=None,csrf=None):
            conn=http.client.HTTPConnection('127.0.0.1',port)
            headers={'Host':host,'Content-Type':'application/json'}
            if origin is not None:headers['Origin']=origin
            if csrf is not None:headers['X-CSRF-Token']=csrf
            conn.request(method,path,headers=headers,body='{}' if method=='POST' else None)
            response=conn.getresponse();status=response.status;response.read();conn.close();return status
        try:
            for host in ('192.0.2.10:8766','[2001:db8::10]:8766','localhost:8766'):
                self.assertEqual(request('GET','/',host),200)
                self.assertEqual(request('POST','/api/loop-stop',host,'http://'+host,self.console.csrf),200)
            self.assertEqual(request('GET','/','cloudpc.example.com'),200)
            self.assertEqual(request('POST','/api/loop-stop','cloudpc.example.com','https://cloudpc.example.com',self.console.csrf),200)
            for host in ('192.0.2.10:8767','evil.example:8766','192.0.2.10:8766@evil.example','192.0.2.10:8766/path'):
                self.assertEqual(request('GET','/api/state',host),403)
            for origin in (None,'http://evil.example','http://192.0.2.11:8766','http://192.0.2.10:8766.evil.example'):
                self.assertEqual(request('POST','/api/loop-stop','192.0.2.10:8766',origin,self.console.csrf),403)
            self.assertEqual(request('POST','/api/loop-stop','192.0.2.10:8766','http://192.0.2.10:8766','wrong'),403)
            self.assertEqual(request('GET','/healthz',f'127.0.0.1:{port}'),200)
        finally:server.shutdown();server.server_close();thread.join()

    def test_remote_access_opt_in_and_changed_public_port(self):
        server=w.ThreadingHTTPServer(('127.0.0.1',0),w.make_handler(self.console,0))
        port=server.server_address[1]
        def get(host):
            conn=http.client.HTTPConnection('127.0.0.1',port)
            conn.request('GET','/',headers={'Host':host})
            response=conn.getresponse();status=response.status;response.read();conn.close();return status
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            server.RequestHandlerClass=w.make_handler(self.console,port)
            self.assertEqual(get('192.0.2.10:8766'),403)
            server.RequestHandlerClass=w.make_handler(self.console,port,public_port=18766)
            self.assertEqual(get('192.0.2.10:18766'),200)
            self.assertEqual(get('localhost:18766'),200)
            self.assertEqual(get('192.0.2.10:8766'),403)
        finally:server.shutdown();server.server_close();thread.join()

    def test_shutdown_stops_schedule_and_waits_for_current_worker(self):
        self.console.loop=True;self.console.next_run=123;job=Mock();self.console.job=job
        self.console.close()
        self.assertFalse(self.console.loop);self.assertIsNone(self.console.next_run)
        job.join.assert_called_once_with(timeout=85)
        self.assertTrue(self.console.stopping)
        with self.assertRaises(ValueError):self.console.start_job('connect')
        with self.assertRaises(ValueError):self.console.set_loop(True)
        self.console.job=None

    def test_migration_writes_private_json_without_logging_credentials(self):
        payload={'account.local.json':{'auth':{'password':'PRIVATE'}},'live/zte-ice-pin.local.json':{'sha256':'test'}}
        result=subprocess.run([sys.executable,'-X','utf8','-c',migration.IMPORT_CODE],cwd=w.PROTOCOL,
                              input=json.dumps(payload).encode(),capture_output=True,check=True)
        self.assertNotIn(b'PRIVATE',result.stdout+result.stderr)
        for name,value in payload.items():self.assertEqual(w.p.load_json(self.data/name),value)

    def test_migration_only_stopped_service_and_credentials_use_stdin(self):
        with tempfile.TemporaryDirectory() as temp:
            source=pathlib.Path(temp)
            w.p.save_json(source/'account.local.json',{'auth':{'password':'PRIVATE'}})
            args=['docker_import.py','--source',str(source)]
            with patch.object(sys,'argv',args),patch.object(migration.shutil,'which',return_value='docker'),patch.object(migration.subprocess,'run') as run:
                run.return_value.stdout=''
                with contextlib.redirect_stdout(io.StringIO()):migration.main()
                self.assertEqual(run.call_count,3)
                call=run.call_args_list[-1]
                self.assertIn(b'PRIVATE',call.kwargs['input'])
                self.assertNotIn('PRIVATE',repr(call.args))
                self.assertIn('-T',call.args[0])
                run.reset_mock();run.return_value.stdout='running-container'
                with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):migration.main()
                self.assertEqual(run.call_count,1)

    def test_pins_only_import_preserves_logged_in_account_and_session(self):
        original=w.p.load_json(self.console.config_file)
        session=self.data/'live/web-session.local.json';w.p.save_json(session,{'accessTicket':'EXISTING_TICKET'})
        with tempfile.TemporaryDirectory() as temp:
            source=pathlib.Path(temp)
            w.p.save_json(source/'account.local.json',{'auth':{'password':'MUST_NOT_IMPORT'}})
            w.p.save_json(source/'live/zte-cag-pin.local.json',{'url':'https://192.0.2.1:443/cs/test','sha256':'a'*64})
            w.p.save_json(source/'live/zte-ice-pin.local.json',{'gateway':'192.0.2.1:443','sha256':'b'*64})
            args=['docker_import.py','--pins-only','--source',str(source)]
            with patch.object(sys,'argv',args),patch.object(migration.shutil,'which',return_value='docker'),patch.object(migration.subprocess,'run') as run:
                run.return_value.stdout=''
                with contextlib.redirect_stdout(io.StringIO()):migration.main()
                payload=run.call_args_list[-1].kwargs['input']
                self.assertEqual(set(json.loads(payload)),{'live/zte-cag-pin.local.json','live/zte-ice-pin.local.json'})
                self.assertNotIn(b'MUST_NOT_IMPORT',payload)
            subprocess.run([sys.executable,'-X','utf8','-c',migration.IMPORT_CODE],cwd=w.PROTOCOL,input=payload,capture_output=True,check=True)
            self.assertEqual(w.p.load_json(self.console.config_file),original)
            self.assertEqual(w.p.load_json(session),{'accessTicket':'EXISTING_TICKET'})

if __name__=='__main__':unittest.main(verbosity=2)
