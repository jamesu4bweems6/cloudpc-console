"""Bounded ZTE guest entry messages, reconstructed from the iOS SDK.

Only capability exchange, login state, guest login and user mode are supported.
There is no clipboard, file transfer, input injection or guest logout command.
"""
import hashlib, struct
import cloudpc_protocol as p

MAX_MESSAGE = 65536

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
    def __init__(self,send,result,ticket,username=None,password=None):
        self.send=send;self.result=result;self.ticket=ticket
        self.username=username;self.password=password
        self.buffer=bytearray();self.queue=[];self.tokens=0
        self.started=False;self.login_sent=False

    def flush(self):
        while self.queue and self.tokens:
            self.send(107,self.queue.pop(0));self.tokens-=1

    def emit(self,kind,payload=b''):
        raw=message(kind,payload)
        for offset in range(0,len(raw),2048):self.queue.append(raw[offset:offset+2048])
        if len(self.queue)>32:raise p.ProtocolError('来宾发送队列超过限制')
        self.result.setdefault('agentSentTypes',[]).append(kind)
        self.flush()

    def start(self,tokens):
        if self.started:return
        self.started=True;self.tokens=tokens
        self.result['guestAgentConnected']=True
        self.send(106,struct.pack('<I',0xffffffff))
        # Only the generic REPLY capability; no display configuration/clipboard.
        self.emit(6,struct.pack('<III',1,1<<2,0))
        self.emit(16,struct.pack('<I',0))

    def login(self):
        if self.started and not self.login_sent:
            # user_logon_type!0xe1bf4c sends password login type 0 as ONE byte.
            self.emit(82,b'\0')
            self.emit(19,login_payload(self.ticket,self.username,self.password))
            self.login_sent=True;self.result['guestLoginSent']=True

    def receive(self,kind,payload):
        if kind==107:self.start(struct.unpack('<I',payload)[0] if len(payload)==4 else 0)
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
            if struct.unpack_from('<I',body)[0]:self.emit(6,struct.pack('<III',0,1<<2,0))
        elif kind==16:
            if len(body)!=4:raise p.ProtocolError('来宾登录状态长度异常')
            state=struct.unpack('<I',body)[0]
            self.result['guestLogonState']=state
            if state:
                self.result['guestSessionEntered']=True
            # A Windows lock screen is already a desktop session. Querying
            # its login state must not implicitly submit Windows credentials.
