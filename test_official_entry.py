"""Compare entry flow against recorded execution of the original ARM64 SDK.

Fixture payloads are synthetic. The native password sender was intercepted;
its real inner-body construction has separate RSA/native encoding coverage.
"""
import json,pathlib,struct,unittest
from unittest.mock import Mock,patch
import cloudpc_protocol as p
import zte_guest_agent as a
import zte_gateway_probe as g

class OfficialEntryChecks(unittest.TestCase):
    def test_original_sdk_event_order_and_payloads(self):
        fixture=json.loads((pathlib.Path(__file__).parent/'fixtures/official-guest-entry.json').read_text())
        for case in fixture['cases']:
            with self.subTest(case=case['name']):
                send=Mock();result={}
                agent=a.GuestAgent(send,result,'12345678','test.user','p a!',case['autoLogin'],
                                   server_type=case['serverType'],settings=case['settings'])
                agent.start(600)
                for stage in case['stages']:
                    before=send.call_count
                    if stage['inputGuestState']=='capabilities':
                        agent.handle(6,struct.pack('<II',0,(1<<17) if case['policyCapability'] else 0))
                    else:agent.handle(16,struct.pack('<I',stage['inputGuestState']))
                    expected=[]
                    for event in stage['events']:
                        if event['call']=='password_login_sender':
                            expected.extend([(82,b'\0'),(19,a.login_payload('12345678','test.user','p a!'))])
                        elif event['call']=='send_agent_data':
                            expected.append((event['type'],bytes.fromhex(event['payloadHex'])))
                    observed=[]
                    for call in send.call_args_list[before:]:
                        self.assertEqual(call.args[0],107)
                        wire=call.args[1];proto,typ,opaque,size=struct.unpack_from('<IIQI',wire)
                        self.assertEqual((proto,opaque,size),(1,0,len(wire)-20))
                        observed.append((typ,wire[20:]))
                    self.assertEqual(observed,expected)
                    self.assertEqual(agent.auto_login_pending,bool(stage['autoLoginFlag']))

    def test_policy_capability_is_required_and_exact_string_flags_are_used(self):
        send=Mock();result={}
        agent=a.GuestAgent(send,result,'12345678',settings={'--hub-ratio':'1','--play-lockscreen':'1'})
        agent.start(20);agent.handle(6,struct.pack('<II',0,0))
        self.assertNotIn('guestLockPolicySent',result)
        agent.handle(6,struct.pack('<II',0,1<<17))
        self.assertEqual(result['guestLockPolicyFlags'],3)
        self.assertEqual(send.call_args.args[1],a.message(120,struct.pack('<I',3)))

    def test_credentials_can_be_repeated_by_sdk_events_but_have_a_connection_bound(self):
        agent=a.GuestAgent(Mock(),{},'12345678','test.user','password',server_type='sy')
        agent.start(600)
        for _ in range(8):agent.handle(16,struct.pack('<I',0))
        self.assertEqual(agent.result['guestLoginAttempts'],8)
        with self.assertRaises(p.ProtocolError):agent.handle(16,struct.pack('<I',0))

    def test_continuous_state_does_not_fabricate_initial_entry_ack(self):
        agent=a.GuestAgent(Mock(),{},'12345678');agent.start(20)
        agent.handle(79,struct.pack('<IIII',1,0,0,0))
        self.assertNotIn('guestSessionEntered',agent.result)
        self.assertTrue(agent.result['guestUserModeSent'])
        agent.handle(16,struct.pack('<I',1));agent.handle(79,bytes(16))
        self.assertTrue(agent.result['guestSessionEntered'])
        agent.handle(16,struct.pack('<I',0));self.assertFalse(agent.result['guestSessionEntered'])

    def test_version_and_policy_feedback_are_bounded_and_not_policy_acceptance(self):
        agent=a.GuestAgent(Mock(),{},'12345678')
        agent.handle(24,struct.pack('<II',1,11)+b'V7.24.30_41\0')
        self.assertEqual(agent.result['guestAgentVersion'],'V7.24.30_41')
        agent.handle(121,struct.pack('<I',0))
        self.assertEqual(agent.result['guestLockDisconnectReply'],0)
        self.assertNotIn('guestLockPolicyAccepted',agent.result)
        for kind,body in ((24,b'bad'),(24,struct.pack('<II',1,50)+b'v'),(79,b''),(121,b'bad')):
            with self.assertRaises(p.ProtocolError):agent.handle(kind,body)

    def test_returned_control_parameters_are_preserved_without_duplicate_options(self):
        connect='-p 5900 -h localhost -k 12345678 --vmid M1 --type ice --proxy-sport 443'
        value={'result':0,'success':True,'connectStr':connect+' --server-type sy --al 0 --hub-ratio 1 --play-lockscreen 0 --user-mode 7 --watch-mode 0 --accessToken synthetic-token --token-type 1'}
        options=g.connection_options({'machineId':'M1'},value)
        self.assertEqual(options['--user-mode'],'7');self.assertEqual(options['--accessToken'],'synthetic-token')
        self.assertEqual(options['--logon-noAD'],'0')
        for tail in (' --hub-ratio 0',' --logon-noAD',' --logon-noAD --logon-type 2'):
            with self.assertRaises(p.ProtocolError):g.connection_options({'machineId':'M1'},dict(value,connectStr=value['connectStr']+tail))

    def test_sy_credentials_are_sent_even_when_auto_login_is_disabled(self):
        agent=a.GuestAgent(Mock(),{},'12345678','test.user','password',False,server_type='sy')
        agent.start(20);agent.handle(6,struct.pack('<II',0,0))
        self.assertEqual(agent.result['guestLoginStages'],['capabilities'])
        agent.handle(16,struct.pack('<I',0))
        self.assertEqual(agent.result['guestLoginStages'],['capabilities','logon-state'])

    def test_native_no_ad_and_empty_password_uac_login_types(self):
        for settings,expected in (({'--logon-noAD':'1','--uactoken':'test-uac'},b'\1'+b'test-uac'.ljust(256,b'\0')),
                                  ({'--logon-noAD':'0','--logon-type':'2'},b'\1'+bytes(256)),
                                  ({'--logon-noAD':'0'},b'\0')):
            with self.subTest(settings=settings):
                send=Mock();agent=a.GuestAgent(send,{},'12345678','test.user','',server_type='sy',settings=settings)
                agent.start(20);before=send.call_count;agent.handle(6,struct.pack('<II',0,0))
                wire=[call.args[1] for call in send.call_args_list[before:]]
                if settings['--logon-noAD']=='1':self.assertEqual(wire.pop(0),a.message(85,b'\1'))
                self.assertEqual(wire[0],a.message(82,expected))
                self.assertEqual(wire[1],a.message(19,a.login_payload('12345678','test.user','')))

    def test_native_cli_al_maps_to_noad_before_credentials(self):
        fixture=json.loads((pathlib.Path(__file__).parent/'fixtures/official-login-options.json').read_text())
        self.assertEqual(fixture['records'][0]['property'],'logon-noAD')
        base='-p 5900 -h localhost -k 12345678 --vmid M1 --type ice --proxy-sport 443'
        for flag in ('0','1'):
            with self.subTest(al=flag):
                value={'result':0,'success':True,'connectStr':base+' --al '+flag+' --logon_type 2'}
                settings=g.connection_options({'machineId':'M1'},value)
                self.assertEqual(settings['--logon-noAD'],flag)
                self.assertEqual(settings['--logon-type'],'2')
                send=Mock();agent=a.GuestAgent(send,{},'12345678','test.user','',True,settings=settings)
                agent.start(20);before=send.call_count;agent.handle(6,struct.pack('<II',0,0))
                wire=[call.args[1] for call in send.call_args_list[before:]]
                self.assertEqual(wire,([a.message(85,b'\1')] if flag=='1' else [])+
                    [a.message(82,b'\1'+bytes(256)),a.message(19,a.login_payload('12345678','test.user',''))])
                self.assertFalse(agent.auto_login_pending)
        with self.assertRaises(p.ProtocolError):
            g.connection_options({'machineId':'M1'},dict(value,connectStr=base+' --al 1 --logon-noAD 0'))

    def test_session_pending_login_default_is_independent_of_cli_al(self):
        import tempfile
        result={'desktopFrameReceived':True,'guestLogonState':1,'guestSessionEntered':True}
        raw=Mock();raw.pending.return_value=0
        with tempfile.TemporaryDirectory() as root,patch.object(g,'GuestAgent') as factory,patch.object(g.time,'monotonic',side_effect=[0,1,7,7]):
            g.control_session(raw,False,pathlib.Path(root),result,5,None,{'-k':'12345678','--al':'0'},bytes(32))
        self.assertIs(factory.call_args.args[5],True)

if __name__=='__main__':unittest.main(verbosity=2)
