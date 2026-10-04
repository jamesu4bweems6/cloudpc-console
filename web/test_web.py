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

    def test_connection_diagnostics_use_fixed_hints_without_raw_exceptions(self):
        result=w.safe_result({'success':False,'errorType':'SSLError','diagnosticCode':'CAG_TLS_NO_PIN',
                              'failedStage':'connection_parameters','errorHint':'TOKEN_PRIVATE','rawError':'PASSWORD_PRIVATE'})
        self.assertIn('CAG',result['errorHint']);self.assertIn('证书',result['errorHint'])
        self.assertEqual(result['failedStage'],'connection_parameters')
        self.assertNotIn('PRIVATE',json.dumps(result))
        legacy=w.safe_result({'success':False,'errorType':'SSLError','gatewayAuthenticated':None})
        self.assertIn('CAG',legacy['errorHint'])

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
