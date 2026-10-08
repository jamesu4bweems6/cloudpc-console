"""Offline web integration checks; no production requests or SMS."""
import http.client,json,pathlib,tempfile,threading,unittest
from unittest.mock import patch,Mock
import server as w

class WebChecks(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name)
        cfg={'auth':{'mobile':'13812345678','username':'USER_PRIVATE','password':'PASSWORD_PRIVATE'},
             'common':{'deviceUid':'test'},'target':{'machineId':'mine','machineName':'我的电脑'}}
        w.p.save_json(self.root/'account.local.json',cfg)
        w.p.save_json(self.root/'live/sms-session.local.json',{'accessTicket':'TICKET_PRIVATE','accessToken':'TOKEN_PRIVATE'})
        w.p.save_json(self.root/'live/sms-devices.local.json',{'body':{'machineList':[{'machineId':'mine','machineName':'我的电脑',
                   'originCompanyCode':'ZTE','machineStatus':'available','adPassword':'AD_PRIVATE'}]}})
        self.patch=patch.object(w,'PROTOCOL',self.root);self.patch.start();self.console=w.Console(start_scheduler=False)
    def tearDown(self):self.patch.stop();self.temp.cleanup()

    def test_state_does_not_expose_credentials(self):
        state=self.console.state();raw=json.dumps(state)
        for secret in ('PASSWORD_PRIVATE','USER_PRIVATE','TICKET_PRIVATE','TOKEN_PRIVATE','AD_PRIVATE','13812345678'):
            self.assertNotIn(secret,raw)
        self.assertTrue(state['sessionAvailable']);self.assertFalse(state['expiryRenewalVerified'])

    def test_blank_credentials_preserve_existing_and_bounds_reject(self):
        self.console.settings({'password':'','intervalHours':6,'holdSeconds':20})
        self.assertEqual(w.p.load_json(self.root/'account.local.json')['auth']['password'],'PASSWORD_PRIVATE')
        with self.assertRaises(ValueError):self.console.settings({'intervalHours':0})
        self.console.settings({'intervalHours':24})
        self.assertEqual(self.console.state()['intervalHours'],24)
        with self.assertRaises(ValueError):self.console.settings({'intervalHours':25})
        with self.assertRaises(ValueError):self.console.settings({'targetId':'someone-else'})

    def test_busy_and_loop_exclude_auth_mutation(self):
        self.console.busy=True
        with self.assertRaises(ValueError):self.console.start_job('password')
        with self.assertRaises(ValueError):self.console.settings({'password':'new'})
        self.console.busy=False;self.console.loop=True
        with self.assertRaises(ValueError):self.console.start_job('sms-send')
        self.console.set_loop(False);self.assertFalse(self.console.loop);self.assertIsNone(self.console.next_run)

    def test_device_challenge_and_otp_is_not_persisted(self):
        client=Mock();client.config=w.p.load_json(self.root/'account.local.json');client.state={}
        challenge={'errorCode':'30002009','body':{'code':'challenge-secret'}}
        self.console.finish_login(client,challenge)
        client.send_sms.assert_called_once_with('13812345678','trust')
        self.assertEqual(self.console.state()['pending'],'trust')
        response={'errorCode':'200','body':{'accessTicket':'ticket'}}
        client.trust_device.return_value=response
        client.state={'accessTicket':'new-ticket','accessToken':'new-token'}
        with patch.object(self.console,'client',return_value=client):self.console.worker('challenge',{'code':'123456'})
        client.trust_device.assert_called_once_with(challenge['body'],'13812345678','123456','USER_PRIVATE')
        self.assertIsNone(self.console.pending)
        self.assertNotIn('123456',json.dumps(self.console.state()))
        self.assertNotIn('verification_code',w.p.load_json(self.root/'account.local.json')['auth'])

    def test_failed_connection_stops_schedule(self):
        self.console.loop=True;self.console.next_run=123
        with patch.object(self.console,'connect',side_effect=w.p.ProtocolError('failed')):
            self.console.worker('connect',{})
        self.assertFalse(self.console.loop);self.assertIsNone(self.console.next_run)
        self.assertFalse(self.console.busy)

    def test_power_connect_uses_explicit_power_on_flow(self):
        with patch.object(w.threading,'Thread'):
            self.console.start_job('power-connect',{})
        with patch.object(self.console,'connect') as connect:
            self.console.worker('power-connect',{})
        connect.assert_called_once_with(power_on=True)
        self.assertFalse(self.console.busy)

    def test_connection_diagnostics_use_fixed_hints_without_raw_exceptions(self):
        result=w.safe_result({'success':False,'errorType':'SSLError','diagnosticCode':'CAG_TLS_NO_PIN',
                              'failedStage':'connection_parameters','errorHint':'TOKEN_PRIVATE','rawError':'PASSWORD_PRIVATE'})
        self.assertIn('CAG',result['errorHint']);self.assertIn('证书',result['errorHint'])
        self.assertEqual(result['failedStage'],'connection_parameters')
        self.assertNotIn('PRIVATE',json.dumps(result))
        legacy=w.safe_result({'success':False,'errorType':'SSLError','gatewayAuthenticated':None})
        self.assertIn('CAG',legacy['errorHint'])

    def test_expired_session_status_persists_and_blocks_schedule(self):
        session=w.p.load_json(self.console.session_file);session['authRequired']=True
        w.p.save_json(self.console.session_file,session)
        state=self.console.state()
        self.assertTrue(state['authenticationRequired']);self.assertFalse(state['sessionAvailable'])
        with self.assertRaises(ValueError):self.console.set_loop(True)
        restarted=w.Console(start_scheduler=False)
        try:self.assertTrue(restarted.state()['authenticationRequired'])
        finally:restarted.close()

    def test_old_authentication_success_is_not_presented_as_desktop_entry(self):
        old=w.safe_result({'success':True,'desktopProtocolConnected':True})
        self.assertFalse(old['success']);self.assertTrue(old['legacyMainOnly'])
        current=w.safe_result({'success':True,'desktopSessionEntered':True,'desktopFrameReceived':True,'guestLogonState':0})
        self.assertTrue(current['success']);self.assertTrue(current['desktopFrameReceived'])
        self.assertEqual(current['guestLogonState'],0)

    def test_connection_password_recovery_keeps_schedule_running(self):
        result={'stage':'connect-once','success':True,'desktopSessionEntered':True,'sessionRecoveryAttempted':True,'sessionRecovered':True}
        proc=Mock();proc.stdout=iter([json.dumps({'stage':'session-recovery','status':'started'}),
                                   json.dumps({'stage':'session-recovery','status':'success'}),json.dumps(result)])
        proc.returncode=0;self.console.loop=True
        with patch.object(w.subprocess,'Popen',return_value=proc) as spawn:self.console.worker('connect',{})
        spawn.assert_called_once();self.assertTrue(self.console.loop);self.assertIsNotNone(self.console.next_run)
        self.assertTrue(self.console.last_result['sessionRecovered'])
        self.assertTrue(any('密码续登成功' in e['message'] for e in self.console.events))

    def test_devices_auth_failure_persists_without_sending_sms(self):
        client=Mock();client.config=w.p.load_json(self.root/'account.local.json')
        client.state={'accessTicket':'TICKET_PRIVATE','authRequired':True}
        client.prepare_session.side_effect=w.p.AuthenticationRequired('AUTH_TRUST_REQUIRED','30002009')
        with patch.object(self.console,'client',return_value=client):self.console.worker('devices',{})
        client.send_sms.assert_not_called();self.assertTrue(self.console.state()['authenticationRequired'])
        self.assertTrue(any('设备可信短信验证' in e['message'] for e in self.console.events))

    def test_connection_auth_challenge_stops_without_replaying_desktop(self):
        result={'stage':'connect-once','success':False,'errorType':'BusinessError','errorCode':'30002060',
                'diagnosticCode':'AUTH_TWO_FACTOR_REQUIRED','authenticationRequired':True}
        proc=Mock();proc.stdout=iter([json.dumps(result)]);proc.returncode=1;self.console.loop=True
        with patch.object(w.subprocess,'Popen',return_value=proc) as spawn:self.console.worker('connect',{})
        spawn.assert_called_once();self.assertFalse(self.console.loop)
        self.assertIn('双因素短信验证',self.console.last_result['errorHint'])

    def test_successful_manual_login_clears_expired_session_flag(self):
        client=Mock();client.config=w.p.load_json(self.root/'account.local.json')
        client.state={'accessTicket':'NEW_PRIVATE','deviceUid':'test'}
        self.console.finish_login(client,{'errorCode':'200'})
        self.assertFalse(self.console.state()['authenticationRequired']);self.assertTrue(self.console.state()['sessionAvailable'])

    def test_http_host_origin_csrf_and_static_allowlist(self):
        server=w.ThreadingHTTPServer(('127.0.0.1',0),w.make_handler(self.console,0))
        port=server.server_address[1];server.RequestHandlerClass=w.make_handler(self.console,port)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        def request(method,path,headers=None,body=None):
            conn=http.client.HTTPConnection('127.0.0.1',port)
            conn.request(method,path,body=body,headers=headers or {});response=conn.getresponse()
            content=response.read();status=response.status;conn.close();return status,content
        try:
            self.assertEqual(request('GET','/api/state')[0],200)
            self.assertEqual(request('GET','/api/state',{'Host':'evil.example'})[0],403)
            self.assertEqual(request('GET','/../account.local.json')[0],404)
            self.assertEqual(request('POST','/api/loop-stop',{'Content-Type':'application/json'},'{}')[0],403)
            headers={'Content-Type':'application/json','Origin':f'http://127.0.0.1:{port}','X-CSRF-Token':self.console.csrf}
            self.assertEqual(request('POST','/api/loop-stop',headers,'{}')[0],200)
        finally:server.shutdown();server.server_close();thread.join()

if __name__=='__main__':unittest.main(verbosity=2)
