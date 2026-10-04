"""Offline checks for observed ZTE layouts and fragmented transport reads."""
import struct,tempfile,pathlib,unittest
import zte_gateway_probe as g
import cloudpc_protocol as p
from test_protocol import client,ok,STATE

class FragmentSocket:
    def __init__(self,data,fragment=3):self.data=bytearray(data);self.sent=[];self.fragment=fragment
    def recv(self,n):
        out=bytes(self.data[:min(n,self.fragment)]);del self.data[:len(out)];return out
    def sendall(self,data):self.sent.append(data)

class DesktopChecks(unittest.TestCase):
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
