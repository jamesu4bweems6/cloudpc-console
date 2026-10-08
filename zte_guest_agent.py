"""Bounded ZTE guest entry messages, reconstructed from the iOS SDK.

Only capability exchange, login state, guest login and user mode are supported.
There is no clipboard, file transfer, input injection or guest logout command.
"""
import hashlib, struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import cloudpc_protocol as p

MAX_MESSAGE = 65536
# agent_announce_caps!0xe21804: native desktop extensions, without clipboard
# bits 4/5. Match the native vendor handshake while omitting clipboard support.
CAPABILITIES = (0x8a008007, 0x000080c0)

def guest_credentials(machine):
    # ParseSuOperPara!0x11ba6b4 uses customLoginParams.encry, not logonType.
    # AesCbcDecode!0x11b9cd0 leaves non-hex/non-block inputs unchanged.
    username, password = machine.get('adUser'), machine.get('adPassword')
    if (machine.get('customLoginParams') or {}).get('encry') == 1:
        return username, password
    def decode(value):
        if not isinstance(value, str) or not value:
            return value
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            return value
        if len(value) != len(raw)*2 or not raw or len(raw)%16:
            return value
        decryptor = Cipher(algorithms.AES(b'56Acf4c3498fD4c5a0B1fb26947e2daB'),
                           modes.CBC(b'3498fD4c5a0B1fbA')).decryptor()
        plain = decryptor.update(raw)+decryptor.finalize()
        # Native clears last-byte modulo 16 padding, then assigns a C string.
        count = plain[-1]%16
        if count:
            plain = plain[:-count]+bytes(count)
        try:
            return plain.split(b'\0',1)[0].decode('utf-8')
        except UnicodeDecodeError:
            raise p.ProtocolError('来宾 AES 凭据解码失败') from None
    return decode(username), decode(password)

def message(kind, payload=b''):
    if len(payload)>MAX_MESSAGE:raise p.ProtocolError('来宾消息过长')
    return struct.pack('<IIQI',1,kind,0,len(payload))+payload

def login_payload(ticket, username, password):
    # AddSuOperPwdAndNameParm!0x11bfc50 URL-encodes then XORs the
    # credentials. user_logon_info!0xe16d50 XORs the BE lengths and hash.
    if not username or not isinstance(username,str) or not isinstance(password,str):
        raise p.ConnectionError('GUEST_CREDENTIALS_MISSING')
    def encoded(value):
        raw=value.encode('utf-8')
        if b'\0' in raw:raise p.ProtocolError('来宾凭据含有零字节')
        return ''.join(chr(b) if (48<=b<=57 or 65<=b<=90 or 97<=b<=122)
                       else f'%{b:02X}' for b in raw).encode('ascii')+b'\0'
    digest=hashlib.md5(ticket.encode('ascii')).hexdigest().encode('ascii')
    key=5
    for b in digest:key^=b
    if not key:key=10
    fields=(encoded(username),encoded(password),b'.\0',digest+b'\0')
    if any(len(v)>2049 for v in fields):raise p.ProtocolError('来宾凭据超过样本限制')
    plain=struct.pack('>IIII',*(len(v) for v in fields))+b''.join(fields)
    return bytes(b^key for b in plain)

class GuestAgent:
    def __init__(self,send,result,ticket,username=None,password=None,auto_login=False,login_key=None,terminal_info=None):
        self.send=send;self.result=result;self.ticket=ticket
        self.username=username;self.password=password
        self.buffer=bytearray();self.queue=[];self.tokens=0
        self.started=False;self.login_sent=False
        self.auto_login=auto_login
        self.login_key=login_key
        self.terminal_info=terminal_info

    def flush(self):
        while self.queue and self.tokens:
            self.send(107,self.queue.pop(0));self.tokens-=1

    def emit(self,kind,payload=b''):
        raw=message(kind,payload)
        for offset in range(0,len(raw),2048):self.queue.append(raw[offset:offset+2048])
        if len(self.queue)>32:raise p.ProtocolError('来宾发送队列超过限制')
        self.result.setdefault('agentSentTypes',[]).append(kind)
        self.flush()

    def start(self,tokens=None):
        if self.started:return
        self.started=True
        if tokens is not None:self.tokens=tokens
        self.result['guestAgentConnected']=True
        self.send(106,struct.pack('<I',0xffffffff))
        self.emit(6,struct.pack('<III',1,*CAPABILITIES))
        if self.terminal_info:
            raw=self.terminal_info.encode('utf-8')+b'\0'
            if len(raw)>2048:raise p.ProtocolError('终端信息超过样本限制')
            self.emit(143,struct.pack('<I',len(raw))+raw)
        self.emit(16,struct.pack('<I',0))
        # main_handle_init!0xe36548 queries the guest version after logon state.
        self.emit(23,struct.pack('<I',1))

    def login(self):
        if self.started and not self.login_sent:
            # user_logon_type!0xe1bf4c sends password login type 0 as ONE byte.
            payload=login_payload(self.ticket,self.username,self.password)
            if self.login_key:
                try:payload=self.login_key.encrypt(payload,padding.OAEP(mgf=padding.MGF1(hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
                except ValueError:raise p.ProtocolError('来宾登录 RSA 报文无法加密') from None
            self.result['guestLoginEncryption']='rsa2048_oaep_sha1' if self.login_key else 'legacy_xor'
            self.emit(82,b'\0')
            self.emit(19,payload)
            self.login_sent=True;self.result['guestLoginSent']=True

    def receive(self,kind,payload):
        if kind==107:
            if len(payload) not in (0,4):raise p.ProtocolError('来宾连接消息长度异常')
            self.start(struct.unpack('<I',payload)[0] if payload else None)
        elif kind==110:
            if len(payload)!=4:raise p.ProtocolError('来宾令牌消息长度异常')
            self.tokens=min(65536,self.tokens+struct.unpack('<I',payload)[0]);self.flush()
        elif kind==108:
            self.result['guestAgentConnected']=False
            raise p.ConnectionError('GUEST_AGENT_DISCONNECTED')
        elif kind==109:
            self.buffer.extend(payload)
            if len(self.buffer)>MAX_MESSAGE+20:raise p.ProtocolError('来宾接收缓存超过限制')
            while len(self.buffer)>=20:
                protocol,typ,opaque,size=struct.unpack_from('<IIQI',self.buffer)
                if protocol!=1 or size>MAX_MESSAGE:raise p.ProtocolError('来宾消息头不匹配')
                if len(self.buffer)<20+size:break
                body=bytes(self.buffer[20:20+size]);del self.buffer[:20+size]
                self.handle(typ,body)

    def handle(self,kind,body):
        self.result.setdefault('agentMessageTypes',[]).append(kind)
        if kind==6:
            if len(body)<4 or len(body)%4:raise p.ProtocolError('来宾能力消息长度异常')
            self.result['guestCapabilitiesReceived']=True
            if struct.unpack_from('<I',body)[0]:self.emit(6,struct.pack('<III',0,*CAPABILITIES))
        elif kind==16:
            if len(body)!=4:raise p.ProtocolError('来宾登录状态长度异常')
            state=struct.unpack('<I',body)[0]
            self.result['guestLogonState']=state
            self.result['guestSessionEntered']=state==1
            if state==1 and not self.result.get('guestUserModeSent'):
                self.emit(127,struct.pack('<I',3));self.result['guestUserModeSent']=True
            elif state==0 and self.auto_login:self.login()
