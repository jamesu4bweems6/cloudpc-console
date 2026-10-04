"""Offline interoperability and flow checks; no service requests.

PyCryptodome is an independent RSA/HMAC oracle for the cryptography client.
"""
import base64
import copy
import datetime as dt
import json
import pathlib
import tempfile
import unittest
import io
from contextlib import redirect_stdout
from unittest.mock import patch
from urllib.parse import urlsplit, parse_qs

from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import HMAC, SHA1, SHA256
from Crypto.PublicKey import RSA
import cloudpc_protocol as p

PRIVATE = RSA.generate(1024)
PUBLIC = PRIVATE.publickey()
PROFILE = {'base_url': p.BASE_URL, 'access_key': 'test-key', 'signature_secret': 'test-secret',
           'rsa_private_pem': PRIVATE.export_key().decode('ascii'),
           'rsa_public_pem': PUBLIC.export_key().decode('ascii')}
CONFIG = {'common': {'clientType': 'mobile_ios', 'deviceUid': 'test-device', 'deviceName': '测试设备',
    'clientVersion': '3.6.6', 'deviceModel': 'test-model', 'operatingVersion': '18.0',
    'deviceType': 'mobile', 'companyCode': 'ECloud'}, 'target': {'machineId': 'M1', 'machineName': '测试云电脑'}}
STATE = {'accessTicket': 'test-ticket', 'accessToken': 'test-token',
         'clientLoginUid': 'test-login-uuid', 'deviceUid': 'test-device'}

def oracle_decode(encoded):
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) % 128:
        raise AssertionError('Malformed RSA blocks')
    cipher = PKCS1_v1_5.new(PRIVATE)
    chunks = [cipher.decrypt(raw[i:i+128], b'BAD PADDING') for i in range(0, len(raw), 128)]
    return b''.join(chunks)

def oracle_response(value):
    raw = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    cipher = PKCS1_v1_5.new(PUBLIC)
    chunks = [cipher.encrypt(raw[i:i+117]) for i in range(0, len(raw), 117)]
    return {'params': base64.b64encode(b''.join(chunks)).decode('ascii')}

class Response:
    def __init__(self, value, status=200):
        self.value, self.status_code = oracle_response(value), status
    def json(self):
        return self.value

class MockService:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []
    def post(self, url, *, data, headers, timeout, allow_redirects):
        assert urlsplit(url).scheme == 'https'
        assert urlsplit(url).netloc == 'cloudpc.ecloud.10086.cn'
        assert allow_redirects is False
        body = json.loads(oracle_decode(json.loads(data)['params']).decode('utf-8'))
        query = parse_qs(urlsplit(url).query, strict_parsing=True)
        query.pop('Signature')
        canonical = '&'.join(p.component(k) + '=' + p.component(query[k][0]) for k in sorted(query))
        digest = SHA256.new(canonical.encode()).hexdigest()
        text = 'POST\n' + p.percent_encode(urlsplit(url).path) + '\n' + digest
        expected = HMAC.new(('BC_SIGNATURE&'+PROFILE['signature_secret']).encode(), text.encode(), SHA1).hexdigest()
        assert parse_qs(urlsplit(url).query)['Signature'] == [expected]
        self.calls.append((urlsplit(url).path.removeprefix(p.PREFIX), body))
        assert headers['Content-Type'] == 'application/json;charset=uTF-8'
        if not self.replies:
            raise AssertionError('Unexpected additional request')
        reply = self.replies.pop(0)
        return Response(reply)

def ok(body=None):
    return {'state': 'ok', 'errorCode': '200', 'errorMessage': None, 'body': body}

def client(replies, state=None, **kwargs):
    transport = MockService(replies)
    return p.Client(PROFILE, copy.deepcopy(CONFIG), state, transport=transport, **kwargs), transport

class CryptoChecks(unittest.TestCase):
    def test_fixed_signature_vector(self):
        result = p.signed_path(p.PREFIX+'login/verifySms', {'access_key': 'test-key', 'signature_secret':'test-secret'},
            timestamp='2026-10-04T16:00:00Z', nonce='00000000000040008000000000000000')
        self.assertEqual(result, p.PREFIX+'login/verifySms?AccessKey=test-key&SignatureMethod=HmacSHA1&'
            'SignatureNonce=00000000000040008000000000000000&SignatureVersion=V2.0&'
            'Timestamp=2026-10-04T16%3A00%3A00Z&Signature=481410f361be4548477cc119e5e0e3f69398239f')

    def test_uri_and_timestamp_conventions(self):
        self.assertEqual(p.component("你好 +/!*'()~"), "%E4%BD%A0%E5%A5%BD%20%2B%2F!*'()~")
        self.assertEqual(p.percent_encode("/x*~!'()"), "%2Fx%2A~!'()")
        now = dt.datetime(2026, 10, 4, 20, 30, tzinfo=dt.timezone.utc)
        self.assertEqual(p.utc8_timestamp(now), '2026-10-05T04:30:00Z')
        self.assertEqual(p.utc8_timestamp(now.astimezone(dt.timezone(dt.timedelta(hours=8)))), '2026-10-05T04:30:00Z')

    def test_rsa_byte_boundaries_with_independent_implementation(self):
        envelope = p.Envelope(PROFILE)
        for size in (1, 116, 117, 118, 234, 235):
            raw = bytes(i % 256 for i in range(size))
            encoded = envelope.encode_bytes(raw)
            self.assertEqual(len(base64.b64decode(encoded)), ((size+116)//117)*128)
            self.assertEqual(oracle_decode(encoded), raw)
        # A Chinese code point crosses the 117-byte boundary; decode only after joining bytes.
        value = {'x': 'a'*108+'云电脑😀'*75, 'flag': True, 'empty': None}
        self.assertEqual(json.loads(oracle_decode(envelope.wrap(value)['params'])), value)
        self.assertEqual(envelope.unwrap(oracle_response(value)), value)

    def test_malformed_envelope_rejected(self):
        envelope = p.Envelope(PROFILE)
        with self.assertRaises(p.ProtocolError):
            envelope.decode_bytes(base64.b64encode(b'x'*127).decode())
        with self.assertRaises(ValueError):
            envelope.decode_bytes('invalid!')

class FlowChecks(unittest.TestCase):
    def test_password_cli_device_sms_challenge(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            config = copy.deepcopy(CONFIG)
            config['auth'] = {'mobile':'test-mobile', 'username':'test-user', 'password':'test-password'}
            p.save_json(root/'account.json', config)
            p.save_json(root/'profile.json', PROFILE)
            server = MockService([{'errorCode':'30002009', 'body':{'code':'challenge', 'refreshCode':'refresh'}},
                ok(), ok({'accessTicket':'ticket', 'isCurrentDeviceTrustBeforeLogin':False}),
                ok(), ok({'accessToken':'token'})])
            output = io.StringIO()
            argv = ['cloudpc_protocol.py', 'password-login', '--config', str(root/'account.json'),
                    '--session', str(root/'session.json'), '--profile', str(root/'profile.json')]
            with patch('sys.argv', argv), patch('requests.Session', return_value=server), \
                 patch('getpass.getpass', return_value='test-sms-code'), redirect_stdout(output):
                p.main()
            self.assertEqual(server.calls[1][1]['codeType'], 'trust')
            self.assertEqual(server.calls[2][1]['code'], 'challenge')
            self.assertEqual(server.calls[2][1]['loginUserName'], 'test-user')
            self.assertEqual(server.calls[3][1]['isTemporary'], 1)
            state = p.load_json(root/'session.json')
            self.assertEqual(state['accessToken'], 'token')
            self.assertNotIn('password', state)
            self.assertNotIn('test-password', output.getvalue())
            self.assertNotIn('test-sms-code', output.getvalue())

    def test_sms_login_and_ticket_exchange(self):
        c, server = client([ok(), ok({'accessTicket': 'ticket', 'isCurrentDeviceTrustBeforeLogin':False}),
                            ok(), ok({'accessToken':'token'})])
        c.send_sms('test-mobile')
        r = c.verify_sms('test-mobile', 'test-code')
        c.finish_login(r)
        self.assertEqual([x[0] for x in server.calls], ['login/sendVerifySms', 'login/verifySms',
                                                      'login/trustOrTemporaryDevice', 'login/verifyAccessTicket'])
        self.assertEqual(server.calls[0][1]['codeType'], 'login')
        self.assertTrue(server.calls[1][1]['isNeedTemporaryDeviceSelection'])
        self.assertEqual(server.calls[2][1]['isTemporary'], 1)
        self.assertEqual(c.state['accessTicket'], 'ticket')
        self.assertEqual(c.state['accessToken'], 'token')
        self.assertNotIn('password', c.state)

    def test_password_payload_and_business_overrides(self):
        c, server = client([ok({'accessTicket':'ticket'}), ok({'accessToken':'token'})])
        c.common['deviceType'] = 'tablet'
        c.finish_login(c.verify_password('test-user', 'password 密码!'))
        body = server.calls[0][1]
        self.assertEqual(body['password'], 'password 密码!')
        self.assertEqual(body['deviceType'], 'mobile')
        self.assertTrue(body['clientNeedTwoFactor'])
        self.assertEqual(body['deviceSystem'], 'iOS_18.0')
        self.assertEqual(c.state['accessToken'], 'token')

    def test_two_factor_challenge_preserved(self):
        challenge = {'mobile':'test-mobile', 'code':'test-challenge', 'refreshCode':'test-refresh'}
        c, server = client([{'errorCode':'30002060', 'body':challenge}, ok(),
                           ok({'accessTicket':'ticket'}), ok({'accessToken':'token'})])
        r = c.verify_password('user', 'password')
        self.assertEqual(r['errorCode'], '30002060')
        c.send_sms('test-mobile', 'twoFactorAuth')
        r = c.verify_two_factor(r['body'], 'user', 'password', 'test-mobile', 'code')
        c.finish_login(r)
        self.assertEqual(server.calls[2][1]['code'], 'test-challenge')
        self.assertEqual(server.calls[2][1]['refreshCode'], 'test-refresh')
        self.assertIsNone(server.calls[2][1]['source'])

    def test_multi_company_requires_selection(self):
        c, server = client([])
        r = {'errorCode':'10002034', 'body':{'code':'challenge'}}
        with self.assertRaises(p.ProtocolError):
            c.finish_login(r)
        self.assertEqual(server.calls, [])
        c, server = client([ok({'accessTicket':'ticket'}), ok({'accessToken':'token'})])
        c.finish_login(r, selected_username='chosen-user')
        self.assertEqual(server.calls[0][1]['username'], 'chosen-user')
        self.assertEqual(server.calls[0][1]['code'], 'challenge')

    def test_http_200_business_error_is_failure(self):
        c, server = client([{'errorCode':'401', 'body':{'accessTicket':'should-not-be-used'}}])
        with self.assertRaises(p.BusinessError):
            c.verify_password('user', 'wrong-password')
        self.assertEqual(len(server.calls), 1)
        self.assertFalse(c.state.get('accessToken'))

    def test_report_connect_id_and_cleanup(self):
        c, server = client([ok({'loginUid':'server-login'}), ok(), ok({'connectId':'server-connect'}), ok(), ok()], STATE)
        result = c.report_probe(CONFIG['target'])
        self.assertEqual([x[0] for x in server.calls], ['login/recordDeviceInfo', 'session/updateSessionStatus', 'session/machineConnect',
                    'session/updateSessionStatus', 'session/updateSessionStatus'])
        self.assertEqual(server.calls[1][1]['connectList'], [])
        self.assertEqual(server.calls[1][1]['loginStatus'], '0')
        self.assertEqual(server.calls[2][1]['ticket'], 'test-ticket')
        for i, connected in ((3, True), (4, False)):
            body = server.calls[i][1]
            self.assertEqual(body['loginUid'], 'server-login')
            self.assertEqual(body['connectList'], [{'connectId':'server-connect', 'connectStatus':connected}])
            self.assertEqual(body['loginStatus'], '0')
        self.assertNotIn('pendingConnectId', c.state)
        self.assertFalse(result['expiryRenewalVerified'])

    def test_missing_connect_id_stops_status_reports(self):
        c, server = client([ok({'loginUid':'server-login'}), ok(), ok({})], STATE)
        with self.assertRaises(p.ProtocolError):
            c.report_probe(CONFIG['target'])
        self.assertEqual(len(server.calls), 3)

    def test_failed_connected_report_still_closes(self):
        c, server = client([ok({'loginUid':'L'}), ok(), ok({'connectId':'C'}), {'errorCode':'401'}, ok()], STATE)
        with self.assertRaises(p.BusinessError):
            c.report_probe(CONFIG['target'])
        self.assertFalse(server.calls[-1][1]['connectList'][0]['connectStatus'])
        self.assertNotIn('pendingConnectId', c.state)

    def test_failed_close_keeps_pending_id_for_recovery(self):
        c, server = client([ok({'loginUid':'L'}), ok(), ok({'connectId':'C'}), ok(), {'errorCode':'500'}], STATE)
        with self.assertRaises(p.BusinessError):
            c.report_probe(CONFIG['target'])
        self.assertEqual(c.state['pendingConnectId'], 'C')

    def test_unauthenticated_report_does_not_send(self):
        c, server = client([])
        with self.assertRaises(p.ProtocolError):
            c.report_probe(CONFIG['target'])
        self.assertEqual(server.calls, [])

if __name__ == '__main__':
    unittest.main(verbosity=2)
