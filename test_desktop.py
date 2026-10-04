"""Offline checks for observed ZTE layouts and fragmented transport reads."""
import struct,tempfile,pathlib,unittest
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

if __name__=='__main__':unittest.main(verbosity=2)
