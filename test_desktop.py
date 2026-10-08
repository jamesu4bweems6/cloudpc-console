"""Offline checks for observed ZTE layouts and fragmented transport reads."""
import contextlib,io,json,struct,sys,tempfile,pathlib,unittest
import connect_once as connection
import zte_gateway_probe as g
import cloudpc_protocol as p
import zte_connection as z
from unittest.mock import Mock,patch
from test_protocol import client,ok,STATE

class FragmentSocket:
    def __init__(self,data,fragment=3):self.data=bytearray(data);self.sent=[];self.fragment=fragment
    def recv(self,n):
        out=bytes(self.data[:min(n,self.fragment)]);del self.data[:len(out)];return out
    def sendall(self,data):self.sent.append(data)

class DesktopChecks(unittest.TestCase):
    def test_default_pins_only_seed_missing_files_and_never_replace_user_state(self):
        with tempfile.TemporaryDirectory() as root:
            code=pathlib.Path(root)/'code';data=pathlib.Path(root)/'data'
            cag={'url':'https://192.0.2.1:443/cs/test','sha256':'a'*64}
            ice={'gateway':'192.0.2.1:443','sha256':'b'*64}
            p.save_json(code/'gateway-pins/zte-cag-pin.json',cag)
            p.save_json(code/'gateway-pins/zte-ice-pin.json',ice)
            account={'auth':{'password':'KEEP_ME'}};session={'accessTicket':'KEEP_TICKET'}
            p.save_json(data/'account.local.json',account);p.save_json(data/'live/web-session.local.json',session)
            with patch.object(p,'HERE',code):
                self.assertEqual(p.ensure_gateway_pins(data),['zte-cag-pin','zte-ice-pin'])
                custom={'url':'https://192.0.2.2:443/cs/test','sha256':'c'*64}
                p.save_json(data/'live/zte-cag-pin.local.json',custom)
                p.save_json(code/'gateway-pins/zte-ice-pin.json',{'gateway':'192.0.2.1:443','sha256':'d'*64})
                self.assertEqual(p.ensure_gateway_pins(data),[])
            self.assertEqual(p.load_json(data/'live/zte-cag-pin.local.json'),custom)
            self.assertEqual(p.load_json(data/'live/zte-ice-pin.local.json'),ice)
            self.assertEqual(p.load_json(data/'account.local.json'),account)
            self.assertEqual(p.load_json(data/'live/web-session.local.json'),session)

    def test_cag_ssl_without_pin_has_safe_diagnostic_and_keeps_ca_verification(self):
        with tempfile.TemporaryDirectory() as root:
            data=pathlib.Path(root)
            session=Mock();session.__enter__=Mock(return_value=session);session.__exit__=Mock(return_value=False)
            session.post.side_effect=z.requests.exceptions.SSLError('private host / password / ticket')
            with patch.object(p,'DATA_DIR',data),patch.object(z,'sdk_values',return_value=(b'a'*16,'zh')), \
                 patch.object(z,'request_spec',return_value=('https://192.0.2.1:443/cs/test',{},{})), \
                 patch.object(z.requests,'Session',return_value=session):
                with self.assertRaises(p.ConnectionError) as caught:z.fetch_parameters({},data/'parameters')
            self.assertEqual(caught.exception.diagnostic_code,'CAG_TLS_NO_PIN')
            self.assertEqual(caught.exception.error_type,'SSLError')
            self.assertNotIn('private host',str(caught.exception))
            self.assertNotIn('verify',session.post.call_args.kwargs)
            session.mount.assert_not_called()

    def test_cag_pin_mismatch_stops_before_post_and_pinned_ssl_is_distinct(self):
        with tempfile.TemporaryDirectory() as root:
            data=pathlib.Path(root);url='https://192.0.2.1:443/cs/test'
            for stored_url,code in (('https://192.0.2.2:443/cs/test','CAG_PIN_GATEWAY_MISMATCH'),(url,'CAG_TLS_PINNED_FAILURE')):
                p.save_json(data/'live/zte-cag-pin.local.json',{'url':stored_url,'sha256':'a'*64})
                session=Mock();session.__enter__=Mock(return_value=session);session.__exit__=Mock(return_value=False)
                session.post.side_effect=z.requests.exceptions.SSLError('private ticket')
                with patch.object(p,'DATA_DIR',data),patch.object(z,'sdk_values',return_value=(b'a'*16,'zh')), \
                     patch.object(z,'request_spec',return_value=(url,{},{})),patch.object(z.requests,'Session',return_value=session):
                    with self.assertRaises(p.ConnectionError) as caught:z.fetch_parameters({},data/'parameters')
                self.assertEqual(caught.exception.diagnostic_code,code)
                if stored_url!=url:session.post.assert_not_called()
                else:
                    adapter=session.mount.call_args.args[1]
                    self.assertEqual(adapter.allowed_url,url);self.assertEqual(adapter.fingerprint,'a'*64)

    def test_observed_extended_reply_caps_offset(self):
        # Service 2026-10-04 18:09:38: body 190 bytes, counts at 166/170,
        # caps_offset at 178 (NOT the standard 174). Sensitive fields zeroed.
        reply=bytearray(190)
        struct.pack_into('<IIIIII',reply,166,1,1,0,182,0x502,0x84709)
        self.assertEqual(g.link_capabilities(reply),([0x502],[0x84709]))
        for offset in (174,191,0xffffffff):
            struct.pack_into('<I',reply,178,offset)
            with self.assertRaises(p.ProtocolError):g.link_capabilities(reply)

    def test_fragmented_ice_stream_skips_other_link(self):
        # Includes a control frame, another link, and fragmented own payloads.
        raw=b'\x1a\x01\x00\x00'+b'\x0a\x02\x03\x00xxx'+b'\x0a\x01\x02\x00RE'+b'\x0a\x01\x02\x00DQ'
        with tempfile.TemporaryDirectory() as root:
            stream=g.IceStream(FragmentSocket(raw,1),pathlib.Path(root),{})
            self.assertEqual(g.read_exact(stream,4),b'REDQ')
            self.assertEqual(stream.count,4)

    def test_close_frame_and_eof_are_failures(self):
        with tempfile.TemporaryDirectory() as root:
            stream=g.IceStream(FragmentSocket(b'\x2a\x01\x00\x00'),pathlib.Path(root),{})
            with self.assertRaises(p.ProtocolError):stream.recv(1)
        with self.assertRaises(EOFError):g.read_exact(FragmentSocket(b'RE'),4)

    def test_chunked_send_preserves_frame_lengths(self):
        raw=FragmentSocket(b'')
        stream=g.IceStream(raw,pathlib.Path('.'),{})
        data=b'z'*70000;stream.sendall(data)
        self.assertEqual([struct.unpack('<BBH',x[:4]) for x in raw.sent],[(10,1,65535),(10,1,4465)])
        self.assertEqual(b''.join(x[4:] for x in raw.sent),data)

    def test_full_main_header_fragmentation_and_limits(self):
        # Real frame size 83 = native 19-byte header + 64-byte MAIN_INIT.
        wire=struct.pack('<QHIIB',1,103,64,0,0)+bytes(64)
        kind,header,payload=g.read_main_message(FragmentSocket(wire,1),False)
        self.assertEqual((kind,len(header),len(payload)),(103,19,64))
        with self.assertRaises(p.ProtocolError):
            g.read_main_message(FragmentSocket(struct.pack('<HIB',103,2**20+1,0)),True)

    def test_ticket_refresh_preserves_login_identity(self):
        c,service=client([ok({'accessToken':'new-token'})],STATE)
        c.refresh_ticket()
        self.assertEqual(c.state['accessToken'],'new-token')
        self.assertEqual(c.state['clientLoginUid'],STATE['clientLoginUid'])
        self.assertEqual(service.calls[0][1]['accessTicket'],'test-ticket')

    def test_missing_refresh_token_does_not_replace_existing(self):
        c,_=client([ok({})],STATE)
        with self.assertRaises(p.ProtocolError):c.refresh_ticket()
        self.assertEqual(c.state['accessToken'],STATE['accessToken'])

    def test_prepare_valid_session_never_password_logs_in(self):
        c,service=client([ok({'accessToken':'new-token'}),ok({'machineList':[]})],STATE)
        self.assertEqual(c.prepare_session(c.devices)['body']['machineList'],[])
        self.assertEqual([v[0] for v in service.calls],['login/verifyAccessTicket','user/getDeviceInfo'])
        self.assertFalse(c.session_recovery_attempted)

    def test_expired_ticket_relogs_in_once_and_keeps_pending_disconnect(self):
        state=dict(STATE,pendingConnectId='unfinished',loginUid='old-login')
        c,service=client([{'errorCode':'401'},ok({'accessTicket':'fresh-ticket'}),
                         ok({'accessToken':'fresh-token'}),ok({'machineList':[]})],state)
        c.config['auth']={'username':'test-user','password':'test-password'}
        events=[];c.prepare_session(c.devices,on_recovery=events.append)
        self.assertEqual(events,['started','success'])
        self.assertTrue(c.session_recovered);self.assertTrue(c.session_recovery_attempted)
        self.assertEqual(c.state['accessTicket'],'fresh-ticket');self.assertEqual(c.state['accessToken'],'fresh-token')
        self.assertEqual(c.state['deviceUid'],STATE['deviceUid'])
        self.assertEqual(c.state['pendingConnectId'],'unfinished');self.assertEqual(c.state['loginUid'],'old-login')
        self.assertNotIn('authRequired',c.state)
        self.assertEqual([v[0] for v in service.calls],['login/verifyAccessTicket','login/verify',
                                                     'login/verifyAccessTicket','user/getDeviceInfo'])

    def test_read_401_after_refresh_recovers_once_without_repeated_login(self):
        c,service=client([ok({'accessToken':'new-token'}),{'errorCode':'401'},
                         ok({'accessTicket':'fresh-ticket'}),ok({'accessToken':'fresh-token'}),{'errorCode':'401'}],STATE)
        c.config['auth']={'username':'test-user','password':'test-password'}
        with self.assertRaises(p.BusinessError) as failure:c.prepare_session(c.devices)
        self.assertEqual(failure.exception.code,'401');self.assertTrue(c.state['authRequired'])
        self.assertEqual(sum(path=='login/verify' for path,_ in service.calls),1)
        self.assertEqual(len(service.calls),5)

    def test_sms_or_account_challenge_requires_user_and_sends_no_sms(self):
        for code,hint in (('30002009','AUTH_TRUST_REQUIRED'),('30002060','AUTH_TWO_FACTOR_REQUIRED'),
                          ('10002034','AUTH_ACCOUNT_REQUIRED')):
            with self.subTest(code=code):
                c,service=client([{'errorCode':'401'},{'errorCode':code,'body':{'code':'PRIVATE'}}],STATE)
                c.config['auth']={'username':'test-user','password':'test-password'}
                with self.assertRaises(p.AuthenticationRequired) as failure:c.prepare_session()
                self.assertEqual(failure.exception.diagnostic_code,hint)
                self.assertNotIn('PRIVATE',str(failure.exception))
                self.assertEqual([v[0] for v in service.calls],['login/verifyAccessTicket','login/verify'])
                self.assertTrue(c.state['authRequired']);self.assertFalse(c.session_recovered)

    def test_sms_only_session_cannot_recover_without_password(self):
        c,service=client([{'errorCode':'401'}],STATE)
        c.config['auth']={'mobile':'test-mobile'}
        with self.assertRaises(p.AuthenticationRequired) as failure:c.prepare_session()
        self.assertEqual(failure.exception.diagnostic_code,'AUTH_CREDENTIALS_REQUIRED')
        self.assertEqual(len(service.calls),1);self.assertEqual(c.state['accessTicket'],STATE['accessTicket'])

    def test_bad_password_or_non_401_is_never_retried(self):
        c,service=client([{'errorCode':'401'},{'errorCode':'30001004'}],STATE)
        c.config['auth']={'username':'test-user','password':'wrong-password'}
        with self.assertRaises(p.BusinessError):c.prepare_session()
        self.assertEqual(len(service.calls),2);self.assertTrue(c.state['authRequired'])
        c,service=client([{'errorCode':'500'}],STATE)
        with self.assertRaises(p.BusinessError):c.prepare_session()
        self.assertEqual(len(service.calls),1);self.assertFalse(c.session_recovery_attempted)

    def test_session_identity_mismatch_prevents_password_recovery(self):
        c,service=client([],dict(STATE,deviceUid='another-device'))
        with self.assertRaises(p.ProtocolError):c.prepare_session()
        self.assertEqual(service.calls,[])

    def test_connect_once_persists_recovered_ticket_and_connects_only_once(self):
        machine={'machineId':'M1','originCompanyCode':'ZTE'}
        c,_=client([{'errorCode':'401'},ok({'accessTicket':'fresh-ticket'}),
                    ok({'accessToken':'fresh-token'}),ok({'machineList':[machine]})],STATE)
        c.config['auth']={'username':'test-user','password':'test-password'}
        c.snapshot=Mock(return_value={});c.record_device=Mock();c.session_status=Mock()
        def report(machine):c.state['pendingConnectId']='connection-id';return 'connection-id'
        c.machine_connected=Mock(side_effect=report)
        def gateway(*args,**kwargs):
            kwargs['on_connected']()
            return {'desktopSessionEntered':True,'controlSessionCompleted':True,'desktopProtocolConnected':True,'controlHoldSeconds':15}
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp);config=root/'account.local.json';session=root/'session.local.json'
            p.save_json(config,c.config);p.save_json(session,STATE)
            with patch.object(sys,'argv',['connect_once.py','--config',str(config),'--session',str(session)]),\
                 patch.object(p,'DATA_DIR',root),patch.object(p,'Client',return_value=c),\
                 patch.object(z,'fetch_parameters',return_value={}),patch.object(g,'connection_options',return_value={}),\
                 patch.object(g,'run_gateway',side_effect=gateway) as run,contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(connection.main(),0)
            run.assert_called_once();c.machine_connected.assert_called_once()
            c.session_status.assert_any_call('connection-id',False)
            saved=p.load_json(session);self.assertEqual(saved['accessTicket'],'fresh-ticket')
            self.assertNotIn('pendingConnectId',saved);self.assertNotIn('fresh-ticket',output.getvalue())
            result=p.load_json(next((root/'live').glob('*-connect-once/result.local.json')))
            self.assertTrue(result['sessionRecovered']);self.assertFalse(result['authenticationRequired'])

    def test_connect_once_challenge_persists_expiry_and_never_opens_desktop(self):
        c,_=client([{'errorCode':'401'},{'errorCode':'30002009','body':{'code':'PRIVATE_CHALLENGE'}}],STATE)
        c.config['auth']={'username':'test-user','password':'test-password'};c.snapshot=Mock(return_value={})
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp);config=root/'account.local.json';session=root/'session.local.json'
            p.save_json(config,c.config);p.save_json(session,STATE)
            with patch.object(sys,'argv',['connect_once.py','--config',str(config),'--session',str(session)]),\
                 patch.object(p,'DATA_DIR',root),patch.object(p,'Client',return_value=c),\
                 patch.object(z,'fetch_parameters') as fetch,patch.object(g,'run_gateway') as run,\
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(connection.main(),1)
            fetch.assert_not_called();run.assert_not_called()
            self.assertTrue(p.load_json(session)['authRequired'])
            result=p.load_json(next((root/'live').glob('*-connect-once/result.local.json')))
            self.assertEqual(result['diagnosticCode'],'AUTH_TRUST_REQUIRED');self.assertEqual(result['errorCode'],'30002009')
            self.assertTrue(result['authenticationRequired']);self.assertNotIn('PRIVATE_CHALLENGE',output.getvalue())

if __name__=='__main__':unittest.main(verbosity=2)
