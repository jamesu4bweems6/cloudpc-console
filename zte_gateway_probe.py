"""One bounded CAG key exchange, only to the configured desktop's first gateway.

Default sends only the key exchange. --authenticate sends configured guest
credentials; --desktop additionally attempts the direct CAG main channel.
--ice opens the observed ZTE ICE/TLS main channel. connect_once.py obtains
fresh parameters and adds CEM reports while that channel remains connected.
Local proxy frames must not be sent as remote ICE frames.
Wire structure is from SDK send_access_gateway_local_key!0x2094e4.
"""
import datetime as dt,json,secrets,socket,struct,uuid,shlex,sys,ssl,hashlib,time,select
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
import cloudpc_protocol as p
from zte_connection import HERE

def read_exact(sock,n):
    out=bytearray()
    while len(out)<n:
        part=sock.recv(n-len(out))
        if not part: raise EOFError()
        out.extend(part)
    return bytes(out)

def cag_encrypt(raw,client_key,server_key,flags):
    # tn_deal_aes_code!0x20ba80: ASCII hex key; no PKCS padding.
    c=struct.pack('<I',client_key&0xabacacab)
    s=struct.pack('<I',server_key|0x98979798)
    key=(f'{client_key:08x}{server_key:08x}'+
         ''.join(f'{x:02x}' for x in [s[0],s[3],s[2],s[1],c[3],c[1],c[0],c[2]])).encode()
    bits=256 if flags&1 else 128
    # SDK literal intentionally begins "02x", followed by seven substitutions.
    iv=('02x'+f'{c[2]:02X}{c[0]:02X}{c[1]:02x}{c[3]:02X}{s[1]:02x}{s[2]:02x}{s[3]:02X}').encode()[:16]
    raw=raw.ljust(64,b'\0')
    if len(raw)!=64:raise p.ProtocolError('凭据超过样本网关认证固定字段长度')
    mode=modes.CBC(iv) if flags&2 else modes.ECB()
    encryptor=Cipher(algorithms.AES(key[:bits//8]),mode).encryptor()
    return encryptor.update(raw)+encryptor.finalize()

def connection_options(machine,value=None):
    files=sorted((p.DATA_DIR/'live').glob('*-zte-parameters/response.local.json'))
    if value is None:
        if not files: raise p.ProtocolError('需要先取得本人桌面连接参数')
        value=p.load_json(files[-1])
    if value.get('result') not in ('0',0) or not value.get('success'):
        raise p.ProtocolError('桌面参数业务失败')
    args=shlex.split(value['connectStr'])
    options={}
    for name in ['-p','-h','-k','--vmid','--type','--proxy-sport']:
        if args.count(name)!=1:raise p.ProtocolError('必要桌面选项不唯一')
        options[name]=args[args.index(name)+1]
    if options['--vmid']!=machine['machineId'] or options['--type']!='ice':
        raise p.ProtocolError('仅支持当前本人 ICE 桌面参数')
    return options

def link_capabilities(reply):
    if len(reply)<182:raise p.ProtocolError('桌面能力头被截断')
    ncommon,nchannel=struct.unpack_from('<II',reply,166)
    offset=struct.unpack_from('<I',reply,178)[0]
    if max(ncommon,nchannel)>1024 or offset<182 or offset+(ncommon+nchannel)*4>len(reply):
        raise p.ProtocolError('桌面能力数组长度不一致')
    common=list(struct.unpack_from('<'+'I'*ncommon,reply,offset))
    channel=list(struct.unpack_from('<'+'I'*nchannel,reply,offset+ncommon*4))
    return common,channel

def read_main_message(sock,mini):
    # ZTE adds one flags byte: recv_msg!0xdda418 / write_msg!0xdd7814.
    hdr=read_exact(sock,7 if mini else 19)
    if mini:kind,length,_=struct.unpack('<HIB',hdr)
    else:_,kind,length,_,_=struct.unpack('<QHIIB',hdr)
    if length>1024*1024:raise p.ProtocolError('主通道消息超过实验限制')
    return kind,hdr,read_exact(sock,length)

def control_session(sock,mini,directory,result,hold_seconds,on_connected):
    serial=0
    def send(kind,payload=b''):
        nonlocal serial
        serial+=1
        hdr=struct.pack('<HIB',kind,len(payload),0) if mini else struct.pack('<QHIIB',serial,kind,len(payload),0,0)
        sock.sendall(hdr+payload)
        result.setdefault('mainSentTypes',[]).append(kind)
    # main_handle_init!0xe365fc requests version; 0xe3662c attaches channels.
    send(114,struct.pack('<II',1,1));send(104)
    if on_connected:on_connected()
    started=time.monotonic();deadline=started+hold_seconds
    raw=sock.sock if isinstance(sock,IceStream) else sock
    for i in range(32):
        remaining=deadline-time.monotonic()
        if remaining<=0:break
        buffered=isinstance(sock,IceStream) and bool(sock.buffer)
        if not buffered and not raw.pending() and not select.select([raw],[],[],remaining)[0]:break
        raw.settimeout(max(.1,min(8,remaining)))
        kind,hdr,payload=read_main_message(sock,mini)
        (directory/f'control-{i:02d}-{kind}.local.bin').write_bytes(hdr+payload)
        result.setdefault('mainMessageTypes',[]).append(kind)
        if kind==4:
            if len(payload)<12:raise p.ProtocolError('PING 消息被截断')
            send(3,payload[:12])
        elif kind==104:result['channelsListReceived']=True
    else:raise p.ProtocolError('主通道控制消息数量超过实验限制')
    result.update(controlHoldSeconds=round(time.monotonic()-started,2),controlSessionCompleted=True)

def main_channel(sock,options,serial,directory,result,on_connected=None,hold_seconds=0):
    # Direct CAG channel path. add_link_to_proxy_by_socket is local IPC;
    # the remote multiplexed ICE path has a different frame layout.
    result.setdefault('transportPath','direct_cag_main')
    # spice_channel_send_link!0xde4178: ZTE extended link body = 705 bytes.
    # The ticket is embedded at +34. ICE then sends 128 zero bytes after reply
    # (SpiceChannelWrite_if!0xde6dfc), rather than standard RSA ticket auth.
    body=bytearray(705)
    struct.pack_into('<IBBIII',body,0,0,1,0,1,0,705)
    struct.pack_into('<I',body,27,20)
    ticket=options['-k'].encode('ascii')
    if len(ticket)!=8:raise p.ProtocolError('当前样本要求 8 字节 ICE 票据')
    body[34:42]=ticket
    vmid=options['--vmid'].encode('ascii')
    body[42:42+len(vmid)]=vmid
    body[79:95]=serial
    packet=struct.pack('<4sIII',b'REDQ',2,2,len(body)+4)+body+struct.pack('<I',8)
    (directory/'link-request.local.bin').write_bytes(packet)
    sock.sendall(packet)
    header=read_exact(sock,16)
    magic,major,minor,size=struct.unpack('<4sIII',header)
    if magic!=b'REDQ' or major!=2 or not 178<=size<=65536:
        (directory/'unexpected-link-header.local.bin').write_bytes(header)
        raise p.ProtocolError('桌面通道头不符合已还原结构')
    reply=read_exact(sock,size)
    (directory/'link-reply.local.bin').write_bytes(header+reply)
    error=struct.unpack_from('<I',reply)[0]
    result.update(desktopLinkError=error,desktopLinkReplySize=size)
    if error: return
    # ZTE inserts a 4-byte field before caps_offset (recv_link_msg +0xb2).
    common,channel=link_capabilities(reply)
    if channel and channel[0]&(1<<18):
        result['otherClientOnline']=True
        return
    sock.sendall(bytes(128))
    code=struct.unpack('<I',read_exact(sock,4))[0]
    result['desktopAuthCode']=code
    if code:return
    result['desktopChannelAuthenticated']=True
    mini=bool(common and common[0]&8)
    # Read bounded control messages, with no display/input/guest-agent channel.
    for i in range(12):
        kind,hdr,payload=read_main_message(sock,mini)
        (directory/f'main-{i:02d}-{kind}.local.bin').write_bytes(hdr+payload)
        result.setdefault('mainMessageTypes',[]).append(kind)
        if kind==103 and len(payload)>=32:
            result.update(mainInitReceived=True,desktopProtocolConnected=True)
            p.save_json(directory/'main-init.local.json',{
                'sessionConnectionId':struct.unpack_from('<I',payload)[0],
                'rawSize':len(payload)})
            if hold_seconds or on_connected:
                control_session(sock,mini,directory,result,hold_seconds,on_connected)
            return
    raise p.ProtocolError('未收到 MAIN_INIT')

class IceStream:
    """Expose one native virtual link as a byte stream, with bounded frames."""
    def __init__(self,sock,directory,result,link=1):
        self.sock=sock;self.directory=directory;self.result=result
        self.link=link;self.buffer=bytearray();self.count=0
    def sendall(self,data):
        for offset in range(0,len(data),65535):
            chunk=data[offset:offset+65535]
            self.sock.sendall(struct.pack('<BBH',10,self.link,len(chunk))+chunk)
    def recv(self,n):
        while not self.buffer:
            if self.count>=64:raise p.ProtocolError('ICE 接收帧数超过实验限制')
            header=read_exact(self.sock,4)
            kind,link,size=struct.unpack('<BBH',header)
            payload=read_exact(self.sock,size)
            (self.directory/f'ice-frame-{self.count:02d}.local.bin').write_bytes(header+payload)
            self.count+=1
            self.result.setdefault('iceFrameHeaders',[]).append({'type':kind,'link':link,'size':size})
            if kind==42:raise p.ProtocolError('服务端关闭 ICE 通道')
            if kind==10 and link==self.link:self.buffer.extend(payload)
        out=bytes(self.buffer[:n]);del self.buffer[:n];return out

def ice_transport(sock,options,serial,directory,result,on_connected=None,hold_seconds=0,pin=None):
    # send_usbipc_ice_server_port!0xe6226c: 116 bytes, then TLS when
    # connect_type=1. Outer proxy channel uses CAG destination -p.
    result['transportPath']='ice_proxy_tls'
    init=bytearray(116)
    struct.pack_into('<I',init,0,1)
    struct.pack_into('<II',init,8,int(options['--proxy-sport']),2)
    (directory/'ice-init-request.local.bin').write_bytes(init)
    sock.sendall(init)
    result['iceInitSent']=True
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
    with context.wrap_socket(sock) as tunnel:
        cert=tunnel.getpeercert(binary_form=True)
        fingerprint=hashlib.sha256(cert).hexdigest()
        if pin and fingerprint!=pin['sha256']:
            raise p.ConnectionError('ICE_PIN_MISMATCH')
        (directory/'ice-peer.local.der').write_bytes(cert)
        result.update(iceTlsConnected=True,iceTlsVersion=tunnel.version(),
                      iceTlsCertificateValidation='first_observation_sha256_pin' if pin else 'sdk_compatible_unverified')
        p.save_json(directory/'ice-peer.local.json',{'sha256':fingerprint})
        # send_tunnel_link_message!0xeac68c emits a 154-byte body, unlike
        # the 156-byte local IPC body. Link id is allocated locally (1 here).
        route=bytearray(154)
        struct.pack_into('<H',route,0,int(options['--proxy-sport']))
        route[2]=1
        route[4:8]=socket.inet_aton(options['-h'])[::-1]
        route[24:40]=serial
        route[84]=1  # channel type at low byte of native bitfield
        packet=struct.pack('<BBH',26,1,len(route))+route
        (directory/'ice-link-request.local.bin').write_bytes(packet)
        tunnel.sendall(packet)
        result['iceLinkSent']=True
        # send_link_create!0xe64480 returns immediately; the one-byte ack
        # exists only between the native local listener and desktop channel.
        main_channel(IceStream(tunnel,directory,result),options,serial,directory,result,on_connected,hold_seconds)

def run_gateway(machine,options,directory,ice=True,on_connected=None,hold_seconds=0,pin=None,authenticate=True,desktop=False):
    cag=machine['customLoginParams']['cagList'][0]
    if pin and pin['gateway']!=f"{cag['addr']}:{cag['port']}":
        raise p.ConnectionError('ICE_PIN_GATEWAY_MISMATCH')
    directory.mkdir(parents=True,exist_ok=True)
    client_key=secrets.randbits(31)
    body=bytearray(44)
    struct.pack_into('<III',body,0,101,client_key,220)
    serial=uuid.uuid4().hex[:16].encode('ascii')
    body[12:28]=serial
    struct.pack_into('<I',body,28,3|((139 if ice else 129)<<16)|((11 if ice else 1)<<24))
    packet=b'ZTEC'+struct.pack('<H',44)+body
    (directory/'request.local.bin').write_bytes(packet)
    result={'stage':'cag-key-exchange','desktopProtocolConnected':False,'expiryRenewalVerified':False}
    try:
        with socket.create_connection((cag['addr'],int(cag['port'])),timeout=8) as s:
            s.settimeout(8);s.sendall(packet)
            hdr=read_exact(s,6)
            size=struct.unpack_from('<H',hdr,4)[0]
            if hdr[:4]!=b'ZTEC' or size>4096:
                (directory/'unexpected-header.local.bin').write_bytes(hdr)
                raise p.ProtocolError('网关返回头不符合样本协议')
            reply=read_exact(s,size)
            (directory/'response.local.bin').write_bytes(hdr+reply)
            result.update(headerMatched=True,responseSize=size,keyExchangeAccepted=size==44)
            if authenticate and size==44:
                server_key=struct.unpack_from('<I',reply,4)[0]
                flags=struct.unpack_from('<I',reply,28)[0]
                info=bytearray(220)
                struct.pack_into('<H',info,0,int(options['-p']))
                info[4:8]=socket.inet_aton(options['-h'])
                vmid=options['--vmid'].encode('ascii')
                if len(vmid)>39:raise p.ProtocolError('VM ID 字段长度不支持')
                info[20:20+len(vmid)]=vmid
                info[60:124]=cag_encrypt(machine['adUser'].encode('utf-8'),client_key,server_key,flags)
                info[124:188]=cag_encrypt(machine['adPassword'].encode('utf-8'),client_key,server_key,flags)
                (directory/'auth-request.local.bin').write_bytes(info)
                s.sendall(info)
                auth_reply=read_exact(s,36)
                (directory/'auth-response.local.bin').write_bytes(auth_reply)
                code=struct.unpack_from('<I',auth_reply)[0]
                result.update(gatewayAuthCode=code,gatewayAuthenticated=code==200)
                if code==200 and ice:
                    ice_transport(s,options,serial,directory,result,on_connected,hold_seconds,pin)
                elif code==200 and desktop:
                    main_channel(s,options,serial,directory,result)
    except (OSError,EOFError,p.ProtocolError) as exc:
        result['errorType']=getattr(exc,'error_type',type(exc).__name__)
        if isinstance(exc,p.ConnectionError):result['diagnosticCode']=exc.diagnostic_code
        if isinstance(exc,p.BusinessError):result['errorCode']=exc.code
    p.save_json(directory/'result.local.json',result)
    return result

def main():
    cfg=p.load_json(p.DATA_DIR/'account.local.json')
    devices=p.load_json(p.DATA_DIR/'live/sms-devices.local.json')['body']['machineList']
    match=[m for m in devices if m['machineId']==cfg['target']['machineId']]
    if len(match)!=1 or match[0]['originCompanyCode']!='ZTE':
        raise p.ProtocolError('需要唯一匹配本人 ZTE 桌面')
    directory=p.DATA_DIR/'live'/dt.datetime.now().strftime('%Y%m%d-%H%M%S-%f-cag-key')
    authenticate=any(a in sys.argv for a in ('--authenticate','--desktop','--ice'))
    options=connection_options(match[0]) if authenticate else {}
    result=run_gateway(match[0],options,directory,ice='--ice' in sys.argv,
                       authenticate=authenticate,desktop='--desktop' in sys.argv)
    print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__':main()
