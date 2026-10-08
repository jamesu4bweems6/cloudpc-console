"""Bounded ZTE guest entry messages, reconstructed from the iOS SDK.

Capability exchange, entry credentials, policy, tokens and user mode are supported.
There is no clipboard, file transfer, input injection or guest logout command.
"""
import hashlib, re, struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import cloudpc_protocol as p

MAX_MESSAGE = 65536
# agent_announce_caps!0xe21804: native desktop extensions, without clipboard
# bits 4/5. Match the native vendor handshake while omitting clipboard support.
CAPABILITIES = (0x8a008007, 0x000080c0)

def native_integer(value):
    # ZXStrtol(..., 10): missing/non-numeric strings resolve to zero.
    match=re.match(r'[ \t\r\n\v\f]*([+-]?[0-9]+)',str(value or ''))
    return int(match[1]) if match else 0

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
    def __init__(self,send,result,ticket,username=None,password=None,auto_login=False,login_key=None,terminal_info=None,*,server_type='common',settings=None):
        self.send=send;self.result=result;self.ticket=ticket
        self.username=username;self.password=password
        self.buffer=bytearray();self.queue=[];self.tokens=0
        self.started=False;self.login_sent=False
        self.auto_login=auto_login
        self.login_key=login_key
        self.terminal_info=terminal_info
        self.server_type=server_type;self.settings=dict(settings or {})
        self.auto_login_pending=auto_login;self.login_attempts=0
        self.server_capabilities=()

    def supports(self,bit):
        word=bit//32
        return word<len(self.server_capabilities) and bool(self.server_capabilities[word]&(1<<(bit%32)))

    def terminal(self):
        if self.terminal_info:
            raw=self.terminal_info.encode('utf-8')+b'\0'
            if len(raw)>2048:raise p.ProtocolError('终端信息超过样本限制')
            self.emit(143,struct.pack('<I',len(raw))+raw)

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
        self.terminal()
        self.emit(16,struct.pack('<I',0))
        # main_handle_init!0xe36548 queries the guest version after logon state.
        self.emit(23,struct.pack('<I',1))

    def login(self,*,repeat=False,source='manual'):
        if self.started and (repeat or not self.login_sent):
            if self.login_attempts>=8:raise p.ProtocolError('来宾登录请求超过单次连接限制')
            # user_logon_type!0xe1bf4c sends password login type 0 as ONE byte.
            payload=login_payload(self.ticket,self.username,self.password)
            if self.login_key:
                try:payload=self.login_key.encrypt(payload,padding.OAEP(mgf=padding.MGF1(hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
                except ValueError:raise p.ProtocolError('来宾登录 RSA 报文无法加密') from None
            self.result['guestLoginEncryption']='rsa2048_oaep_sha1' if self.login_key else 'legacy_xor'
            no_ad=self.settings.get('--logon-noAD')
            if no_ad is not None and no_ad!='0':self.emit(85,b'\1')
            login_type=b'\0'
            if not self.password:
                token=self.settings.get('--uactoken')
                if token:login_type=b'\1'+self.text_bytes(token)[:255].ljust(256,b'\0')
                elif native_integer(self.settings.get('--logon-type'))==2:login_type=b'\1'+bytes(256)
            self.emit(82,login_type)
            self.emit(19,payload)
            self.login_sent=True;self.result['guestLoginSent']=True
            self.auto_login_pending=False;self.login_attempts+=1
            self.result['guestLoginAttempts']=self.login_attempts
            self.result.setdefault('guestLoginStages',[]).append(source)

    @staticmethod
    def text_bytes(value):
        if not isinstance(value,str):raise p.ProtocolError('来宾文本参数类型异常')
        raw=value.encode('utf-8')
        if b'\0' in raw:raise p.ProtocolError('来宾文本参数含有零字节')
        if len(raw)>60000:raise p.ProtocolError('来宾文本参数超过限制')
        return raw

    def entry_login(self,source):
        # _send_agent_user_logon_info: sy is independent of the pending flag.
        if self.server_type=='sy' or self.auto_login_pending:
            self.login(repeat=True,source=source)

    def logged_on(self):
        # e25034 calls both token helpers before the watch-mode guard.
        token=self.settings.get('--accessToken')
        if token is not None:
            raw=self.text_bytes(token)
            self.emit(124,raw[:511].ljust(512,b'\0'))
            if self.settings.get('--token-type')=='1':
                self.emit(142,struct.pack('<HH',1,len(raw)+1)+raw+b'\0')
        if self.settings.get('--watch-mode') is None:
            mode=(native_integer(self.settings.get('--user-mode'))&0xffffffff) or 3
            self.emit(127,struct.pack('<I',mode));self.result['guestUserModeSent']=True
            self.result['guestUserMode']=mode

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
            if len(body)<4 or len(body)>260 or len(body)%4:raise p.ProtocolError('来宾能力消息长度异常')
            self.server_capabilities=struct.unpack('<'+'I'*((len(body)-4)//4),body[4:])
            self.result['guestCapabilitiesReceived']=True
            if struct.unpack_from('<I',body)[0]:
                self.emit(6,struct.pack('<III',0,*CAPABILITIES));self.terminal()
            self.entry_login('capabilities')
            if self.supports(17):
                flags=(2 if self.settings.get('--hub-ratio')=='1' else 0)|(1 if self.settings.get('--play-lockscreen')=='1' else 0)
                self.emit(120,struct.pack('<I',flags));self.result['guestLockPolicySent']=True
                self.result['guestLockPolicyFlags']=flags
        elif kind==16:
            if len(body)!=4:raise p.ProtocolError('来宾登录状态长度异常')
            state=struct.unpack('<I',body)[0]
            self.result['guestLogonState']=state
            self.result['guestSessionEntered']=state==1
            if state:
                self.auto_login_pending=False;self.logged_on()
            else:self.entry_login('logon-state')
        elif kind==79:
            # Continuous state uses a larger structure; it does not replace
            # the initial state acknowledgement or authorize desktop entry.
            if len(body)<4:raise p.ProtocolError('来宾连续登录状态被截断')
            if struct.unpack_from('<I',body)[0]:self.logged_on()
        elif kind==24:
            if len(body)<8:raise p.ProtocolError('来宾版本响应被截断')
            typ,size=struct.unpack_from('<II',body)
            if typ==1 and size:
                if size>len(body)-8:raise p.ProtocolError('来宾版本长度不一致')
                raw=body[8:8+size].split(b'\0',1)[0][:63]
                try:version=raw.decode('ascii')
                except UnicodeDecodeError:raise p.ProtocolError('来宾版本编码不匹配') from None
                if not re.fullmatch(r'[A-Za-z0-9_.-]+',version):raise p.ProtocolError('来宾版本格式不匹配')
                self.result['guestAgentVersion']=version
        elif kind==121:
            # This is IDE/PPT activity feedback, not an acknowledgement that
            # policy was accepted; the SDK uses it for its idle-exit timer.
            if len(body)!=4:raise p.ProtocolError('来宾锁屏策略反馈长度异常')
            self.result['guestLockDisconnectReply']=struct.unpack('<I',body)[0]
