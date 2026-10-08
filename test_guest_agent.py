"""Offline entry acknowledgement, token flow and multiplexing checks."""
import hashlib,pathlib,struct,tempfile,unittest
from unittest.mock import Mock,patch
import cloudpc_protocol as p
import zte_guest_agent as a
import zte_gateway_probe as g
from test_desktop import FragmentSocket
from test_protocol import client,ok,STATE

class GuestEntryChecks(unittest.TestCase):
    def test_guest_aes_credentials_use_encry_and_preserve_plain_fields(self):
        from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
        from cryptography.hazmat.primitives import padding
        def encrypted(text):
            padder=padding.PKCS7(128).padder()
            raw=padder.update(text.encode())+padder.finalize()
            enc=Cipher(algorithms.AES(b'56Acf4c3498fD4c5a0B1fb26947e2daB'),modes.CBC(b'3498fD4c5a0B1fbA')).encryptor()
            return (enc.update(raw)+enc.finalize()).hex()
        password=encrypted('test-pass!')
        machine={'adUser':'test.user','adPassword':password,'customLoginParams':{'encry':0,'logonType':1}}
        self.assertEqual(a.guest_credentials(machine),('test.user','test-pass!'))
        machine['adUser']=encrypted('domain\\user')
        self.assertEqual(a.guest_credentials(machine),('domain\\user','test-pass!'))
        machine['customLoginParams']['encry']=1
        self.assertEqual(a.guest_credentials(machine),(machine['adUser'],password))
        machine={'adUser':'plain.user','adPassword':'not hex','customLoginParams':{'encry':0}}
        self.assertEqual(a.guest_credentials(machine),('plain.user','not hex'))

    def agent(self,tokens=20):
        result={};send=Mock();agent=a.GuestAgent(send,result,'12345678','test.user','p a!')
        agent.start(tokens);return agent,result,send

    def test_fragmented_caps_and_guest_state_require_complete_ack(self):
        agent,result,send=self.agent()
        wire=a.message(6,struct.pack('<III',1,4,0))+a.message(16,struct.pack('<I',1))
        for b in wire[:-1]:agent.receive(109,bytes([b]))
        self.assertNotIn('guestSessionEntered',result)
        agent.receive(109,wire[-1:]);self.assertTrue(result['guestSessionEntered'])
        self.assertTrue(result['guestCapabilitiesReceived'])
        self.assertEqual(result['agentSentTypes'],[6,16,23,6,127])

    def test_guest_zero_does_not_trigger_windows_login(self):
        agent,result,send=self.agent()
        for _ in range(2):agent.receive(109,a.message(16,struct.pack('<I',0)))
        self.assertFalse(result['guestSessionEntered'])
        self.assertEqual(result['agentSentTypes'],[6,16,23])
        agent.login();agent.login()
        self.assertEqual(result['agentSentTypes'],[6,16,23,82,19])
        self.assertEqual(send.call_args_list[-2].args[1],a.message(82,b'\0'))

    def test_token_exhaustion_queues_without_sending_or_inventing_entry(self):
        agent,result,send=self.agent(0)
        self.assertEqual(send.call_count,1)
        agent.receive(110,struct.pack('<I',1));self.assertEqual(send.call_count,2)
        agent.receive(110,struct.pack('<I',1));self.assertEqual(send.call_count,3)
        agent.receive(110,struct.pack('<I',1));self.assertEqual(send.call_count,4)
        self.assertEqual(agent.queue,[]);self.assertNotIn('guestSessionEntered',result)

    def test_delayed_agent_connected_preserves_main_init_tokens(self):
        send=Mock();result={};agent=a.GuestAgent(send,result,'12345678')
        agent.tokens=600;agent.receive(107,b'')
        self.assertEqual(agent.tokens,597);self.assertEqual(agent.queue,[])
        self.assertEqual(send.call_count,4)
        with self.assertRaises(p.ProtocolError):agent.receive(107,b'bad')

    def test_auto_login_is_once_and_unknown_or_locked_state_cannot_confirm_entry(self):
        send=Mock();result={};agent=a.GuestAgent(send,result,'12345678','test.user','p a!',auto_login=True)
        agent.start(20)
        for state in (0,0,2):agent.handle(16,struct.pack('<I',state))
        self.assertFalse(result['guestSessionEntered'])
        self.assertEqual(result['agentSentTypes'].count(19),1)
        agent.handle(16,struct.pack('<I',1));self.assertTrue(result['guestSessionEntered'])
        agent.handle(16,struct.pack('<I',0));self.assertFalse(result['guestSessionEntered'])
        self.assertEqual(result['agentSentTypes'].count(19),1)

    def test_rsa2048_login_decrypts_to_native_inner_payload(self):
        from cryptography.hazmat.primitives.asymmetric import rsa,padding
        from cryptography.hazmat.primitives import hashes
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        send=Mock();result={}
        agent=a.GuestAgent(send,result,'12345678','test.user','p a!',login_key=key.public_key())
        agent.start(20);agent.login()
        wire=send.call_args.args[1];self.assertEqual(struct.unpack_from('<IIQI',wire),(1,19,0,256))
        plain=key.decrypt(wire[20:],padding.OAEP(mgf=padding.MGF1(hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
        self.assertEqual(plain,a.login_payload('12345678','test.user','p a!'))
        self.assertEqual(result['guestLoginEncryption'],'rsa2048_oaep_sha1')

    def test_extended_rsa_capability_reply_bounds(self):
        reply=bytearray(322);struct.pack_into('<IIIIII',reply,298,1,1,0,314,0x502,0x84709)
        self.assertEqual(g.link_capabilities(reply),([0x502],[0x84709]))
        for offset in (182,323,0xffffffff):
            struct.pack_into('<I',reply,310,offset)
            with self.assertRaises(p.ProtocolError):g.link_capabilities(reply)

    def test_lock_screen_frame_cannot_trigger_connected_report(self):
        result={'desktopFrameReceived':True,'guestLogonState':0,'guestSessionEntered':False};callback=Mock()
        raw=Mock();raw.pending.return_value=0
        with tempfile.TemporaryDirectory() as root,patch.object(g.time,'monotonic',side_effect=[0,31,31]):
            with self.assertRaises(p.ConnectionError) as caught:
                g.control_session(raw,False,pathlib.Path(root),result,15,callback,{'-k':'12345678'},bytes(32))
        self.assertEqual(caught.exception.diagnostic_code,'GUEST_ENTRY_UNCONFIRMED')
        self.assertFalse(result['systemEntryConfirmed']);callback.assert_not_called()

    def test_frame_and_logged_on_state_allow_report_after_confirmation(self):
        result={'desktopFrameReceived':True,'guestLogonState':1,'guestSessionEntered':True};callback=Mock()
        raw=Mock();raw.pending.return_value=0
        with tempfile.TemporaryDirectory() as root,patch.object(g.time,'monotonic',side_effect=[0,1,20,20]):
            g.control_session(raw,False,pathlib.Path(root),result,15,callback,{'-k':'12345678'},bytes(32))
        callback.assert_called_once();self.assertTrue(result['systemEntryConfirmed'])
        self.assertTrue(result['controlSessionCompleted'])

    def test_busy_display_can_hold_session_past_128_auxiliary_frames(self):
        result={'desktopFrameReceived':True,'guestLogonState':1,'guestSessionEntered':True}
        callback=Mock();clock=[0.0];raw=Mock();raw.pending.return_value=1
        with tempfile.TemporaryDirectory() as root:
            stream=g.IceStream(raw,pathlib.Path(root),result)
            stream.consume_auxiliary=Mock();stream.message_ready=Mock(return_value=False)
            def pump():clock[0]+=.1
            stream.pump=Mock(side_effect=pump)
            with patch.object(g.time,'monotonic',side_effect=lambda:clock[0]):
                g.control_session(stream,False,pathlib.Path(root),result,15,callback,{'-k':'12345678'},bytes(32))
        self.assertGreater(stream.pump.call_count,128)
        self.assertGreaterEqual(result['controlHoldSeconds'],15)
        self.assertTrue(result['controlSessionCompleted']);callback.assert_called_once()

    def test_reject_invalid_agent_header_size_and_state(self):
        for wire in (struct.pack('<IIQI',2,6,0,0),struct.pack('<IIQI',1,6,0,65537),a.message(16,b'\0')):
            agent,_,_=self.agent()
            with self.assertRaises(p.ProtocolError):agent.receive(109,wire)

    def test_login_wire_has_native_be_lengths_url_encoding_and_encrypted_nuls(self):
        raw=a.login_payload('12345678','test.user','p a!')
        digest=hashlib.md5(b'12345678').hexdigest().encode();key=5
        for b in digest:key^=b
        key=key or 10;plain=bytes(b^key for b in raw)
        fields=(b'test%2Euser\0',b'p%20a%21\0',b'.\0',digest+b'\0')
        self.assertEqual(struct.unpack('>IIII',plain[:16]),tuple(map(len,fields)))
        self.assertEqual(plain[16:],b''.join(fields))
        with self.assertRaises(p.ConnectionError):a.login_payload('12345678',None,None)

    def test_multiplexer_preserves_other_channel_data(self):
        data=b'\x0a\x01\x03\x00abc'+b'\x0a\x02\x03\x00xyz'
        with tempfile.TemporaryDirectory() as root:
            main=g.IceStream(FragmentSocket(data,1),pathlib.Path(root),{})
            display=g.IceStream(main.sock,pathlib.Path(root),main.result,2,parent=main)
            self.assertEqual(g.read_exact(display,3),b'xyz')
            self.assertEqual(g.read_exact(main,3),b'abc');self.assertEqual(main.count,2)

    def test_auxiliary_ack_and_ping_do_not_inject_input(self):
        with tempfile.TemporaryDirectory() as root:
            raw=FragmentSocket(b'');main=g.IceStream(raw,pathlib.Path(root),{})
            inputs=g.IceStream(raw,pathlib.Path(root),main.result,3,parent=main)
            inputs.mini=False;inputs.serial=0;inputs.ack_count=0;inputs.ack_window=0
            ack=struct.pack('<II',123,1);ping=bytes(12)
            inputs.buffer.extend(struct.pack('<QHIIB',1,3,8,0,0)+ack+struct.pack('<QHIIB',2,4,12,0,0)+ping)
            main.consume_auxiliary()
            kinds=[struct.unpack_from('<H',v,12)[0] for v in raw.sent]
            self.assertEqual(kinds,[1,3,2]);self.assertTrue(all(k<101 for k in kinds))

    def test_power_on_exact_own_shutdown_target_only(self):
        c,service=client([ok({})],STATE);c.config['target']={'machineId':'M1'}
        machine={'machineId':'M1','machineName':'own','originCompanyCode':'ZTE','machineStatus':'shutdown'}
        c.power_on(machine);self.assertEqual(service.calls[0][0],'resource/operate')
        self.assertEqual(service.calls[0][1]['operate'],'available')
        for change in ({'machineId':'other'},{'machineStatus':'available'},{'resourcePoolUid':'pool'},{'originCompanyCode':'other'}):
            with self.assertRaises(p.ProtocolError):c.power_on(dict(machine,**change))
        self.assertEqual(len(service.calls),1)

    def test_desktop_entry_requires_matching_surface_stream_and_complete_video(self):
        with tempfile.TemporaryDirectory() as root:
            display=g.IceStream(FragmentSocket(b''),pathlib.Path(root),{},2)
            frame=struct.pack('<III',28,100,6)+b'\0\0\0\1\x67\x01'
            display.accept_display(123,frame)
            self.assertNotIn('desktopSessionEntered',display.result)
            display.accept_display(122,struct.pack('<IIBB',0,28,13,2)+bytes(41))
            display.accept_display(123,frame)
            self.assertNotIn('desktopSessionEntered',display.result)
            display.accept_display(314,struct.pack('<IIIII',0,1280,960,32,1))
            display.accept_display(123,struct.pack('<III',29,100,6)+frame[12:])
            self.assertNotIn('desktopSessionEntered',display.result)
            display.accept_display(123,frame)
            self.assertNotIn('desktopSessionEntered',display.result)
            self.assertTrue(display.result['desktopDisplayReady'])
            self.assertTrue(display.result['desktopFrameReceived'])
            for bad in (b'\0',struct.pack('<III',28,100,7)+frame[12:]):
                with self.assertRaises(p.ProtocolError):display.accept_display(123,bad)

    def test_main_authentication_cannot_trigger_connected_report(self):
        result={'desktopProtocolConnected':True};callback=Mock()
        raw=Mock();raw.pending.return_value=0
        with tempfile.TemporaryDirectory() as root, patch.object(g.time,'monotonic',side_effect=[0,31,31]):
            with self.assertRaises(p.ConnectionError) as caught:
                g.control_session(raw,False,pathlib.Path(root),result,15,callback,{'-k':'12345678'},bytes(32))
        self.assertEqual(caught.exception.diagnostic_code,'DESKTOP_ENTRY_UNCONFIRMED')
        callback.assert_not_called();self.assertNotIn('controlSessionCompleted',result)

if __name__=='__main__':unittest.main(verbosity=2)
