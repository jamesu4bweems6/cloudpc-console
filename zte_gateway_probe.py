"""One bounded CAG key exchange, only to the configured desktop's first gateway.

Default sends only the key exchange. --authenticate sends configured guest
credentials; --desktop additionally attempts the direct CAG main channel.
--ice opens the observed ZTE ICE/TLS channels. connect_once.py obtains
fresh parameters and reports entry only after a desktop frame is received.
Local proxy frames must not be sent as remote ICE frames.
Wire structure is from SDK send_access_gateway_local_key!0x2094e4.
"""
import datetime as dt,json,secrets,socket,struct,uuid,shlex,sys,ssl,hashlib,time,select
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
import cloudpc_protocol as p
from zte_connection import HERE
from zte_guest_agent import GuestAgent

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
    if not isinstance(value.get('connectStr'),str) or not value['connectStr']:
        raise p.ConnectionError('DESKTOP_PARAMETERS_PENDING')
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

def control_session(sock,mini,directory,result,hold_seconds,on_connected,options,init):
    serial=0
    def send(kind,payload=b''):
        nonlocal serial
        serial+=1
        hdr=struct.pack('<HIB',kind,len(payload),0) if mini else struct.pack('<QHIIB',serial,kind,len(payload),0,0)
        sock.sendall(hdr+payload)
        result.setdefault('mainSentTypes',[]).append(kind)
    agent=GuestAgent(send,result,options['-k'],options.get('_guest_user'),options.get('_guest_password'))
    if struct.unpack_from('<I',init,16)[0]:agent.start(struct.unpack_from('<I',init,20)[0])
    # main_handle_init!0xe365fc requests version; 0xe3662c attaches channels.
    send(114,struct.pack('<II',1,1));send(104)
    reported=False;started=time.monotonic();deadline=started+max(30,hold_seconds)
    raw=sock.sock if isinstance(sock,IceStream) else sock
    for i in range(128):
        if isinstance(sock,IceStream):sock.consume_auxiliary()
        if result.get('desktopSessionEntered') and not reported:
            if on_connected:on_connected()
            reported=True;entered=time.monotonic();deadline=entered+hold_seconds
            result['desktopEntryWaitSeconds']=round(entered-started,2)
        remaining=deadline-time.monotonic()
        if remaining<=0:break
        buffered=isinstance(sock,IceStream) and sock.message_ready(mini)
        if not buffered and not raw.pending() and not select.select([raw],[],[],remaining)[0]:continue
        raw.settimeout(max(.1,min(8,remaining)))
        if isinstance(sock,IceStream) and not buffered:
            sock.pump();sock.consume_auxiliary();continue
        kind,hdr,payload=read_main_message(sock,mini)
        (directory/f'control-{i:02d}-{kind}.local.bin').write_bytes(hdr+payload)
        result.setdefault('mainMessageTypes',[]).append(kind)
        if kind==4:
            if len(payload)<12:raise p.ProtocolError('PING 消息被截断')
            send(3,payload[:12])
        elif kind==104:
            result['channelsListReceived']=True
            if isinstance(sock,IceStream):
                if len(payload)<4:raise p.ProtocolError('显示通道列表被截断')
                count=struct.unpack_from('<I',payload)[0]
                if count>32 or len(payload)!=4+count*2:raise p.ProtocolError('通道列表长度异常')
                for j in range(count):
                    typ,channel_id=payload[4+2*j:6+2*j]
                    if typ in (2,3,4) and not result.get({2:'display',3:'inputs',4:'cursor'}[typ]+'ChannelAuthenticated'):
                        open_desktop_channel(sock,init,directory,result,typ,channel_id)
        else:agent.receive(kind,payload)
    else:raise p.ProtocolError('主通道控制消息数量超过实验限制')
    if not reported:raise p.ConnectionError('DESKTOP_ENTRY_UNCONFIRMED')
    result['controlHoldSeconds']=round(time.monotonic()-entered,2)
    result['controlSessionCompleted']=True

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
    # send_link!0xde4290 defaults watch-mode to 1, stored at 0xde48c0.
    # Leaving this byte zero differs from a normal client entry.
    body[32]=1
    ticket=options['-k'].encode('ascii')
    if len(ticket)!=8:raise p.ProtocolError('当前样本要求 8 字节 ICE 票据')
    body[34:42]=ticket
    vmid=options['--vmid'].encode('ascii')
    body[42:42+len(vmid)]=vmid
    body[79:95]=serial
    packet=struct.pack('<4sIII',b'REDQ',2,2,len(body)+4)+body+struct.pack('<I',8)
    if isinstance(sock,IceStream):sock.link_body=body
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
    if size>=314:raise p.ConnectionError('GUEST_RSA_LINK_UNSUPPORTED')
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
    # Wait for MAIN_INIT before starting the guest agent protocol.
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
                control_session(sock,mini,directory,result,hold_seconds,on_connected,options,payload)
            return
    raise p.ProtocolError('未收到 MAIN_INIT')

def open_desktop_channel(main,init,directory,result,typ,channel_id):
    """Attach advertised display/inputs/cursor; never send keyboard/mouse events."""
    name={2:'display',3:'inputs',4:'cursor'}[typ]
    directory=directory/name;directory.mkdir(exist_ok=True)
    display=IceStream(main.sock,directory,result,link=typ,parent=main)
    route=bytearray(main.route);route[84]=typ;route[85]=channel_id
    main.sock.sendall(struct.pack('<BBH',26,typ,len(route))+route)
    body=bytearray(main.link_body)
    struct.pack_into('<I',body,0,struct.unpack_from('<I',init)[0]);body[4]=typ;body[5]=channel_id
    display.sendall(struct.pack('<4sIII',b'REDQ',2,2,709)+body+struct.pack('<I',8))
    magic,major,minor,size=struct.unpack('<4sIII',read_exact(display,16))
    if magic!=b'REDQ' or major!=2 or not 182<=size<314:raise p.ProtocolError('显示链接响应不匹配')
    reply=read_exact(display,size)
    if struct.unpack_from('<I',reply)[0]:raise p.ProtocolError('显示链接被拒绝')
    common,channel=link_capabilities(reply)
    display.sendall(bytes(128))
    if struct.unpack('<I',read_exact(display,4))[0]:raise p.ProtocolError('显示通道认证失败')
    mini=bool(common and common[0]&8)
    display.mini=mini;display.serial=0;display.ack_window=0;display.ack_count=0
    if typ==2:
        # ZTE marshaller!0xf9f2b4 appends uint32 zero + codec byte 3.
        # Native channel_up!0xdfdfb8 uses ids 1 and cache/window in pixels.
        payload=struct.pack('<BqBiIB',1,4*1024*1024,1,256*1024,0,3)
        hdr=struct.pack('<HIB',101,len(payload),0) if mini else struct.pack('<QHIIB',1,101,len(payload),0,0)
        display.sendall(hdr+payload);display.serial=1
    result[name+'ChannelAuthenticated']=True

class IceStream:
    """Expose one native virtual link as a byte stream, with bounded frames."""
    def __init__(self,sock,directory,result,link=1,parent=None):
        self.sock=sock;self.directory=directory;self.result=result
        self.link=link;self.buffer=bytearray();self.count=0
        self.parent=parent or self
        if parent:self.buffers=parent.buffers
        else:self.buffers={};self.streams={}
        self.buffers[link]=self.buffer
        self.parent.streams[link]=self
    def sendall(self,data):
        for offset in range(0,len(data),65535):
            chunk=data[offset:offset+65535]
            self.sock.sendall(struct.pack('<BBH',10,self.link,len(chunk))+chunk)
    def recv(self,n):
        while not self.buffer:self.pump()
        out=bytes(self.buffer[:n]);del self.buffer[:n];return out

    def pump(self):
        if self.parent.count>=256:raise p.ProtocolError('ICE 接收帧数超过实验限制')
        header=read_exact(self.sock,4)
        kind,link,size=struct.unpack('<BBH',header);payload=read_exact(self.sock,size)
        (self.parent.directory/f'ice-frame-{self.parent.count:03d}.local.bin').write_bytes(header+payload)
        self.parent.count+=1
        self.result.setdefault('iceFrameHeaders',[]).append({'type':kind,'link':link,'size':size})
        if kind==42:raise p.ProtocolError('服务端关闭 ICE 通道')
        if kind==10 and link in self.buffers:
            self.buffers[link].extend(payload)
            if len(self.buffers[link])>1024*1024:raise p.ProtocolError('ICE 通道缓存超过限制')

    def message_ready(self,mini):
        hdrsize=7 if mini else 19
        if len(self.buffer)<hdrsize:return False
        length=struct.unpack_from('<I',self.buffer,2 if mini else 10)[0]
        if length>1024*1024:raise p.ProtocolError('桌面消息超过限制')
        return len(self.buffer)>=hdrsize+length

    def consume_auxiliary(self):
        for link,stream in self.parent.streams.items():
            if link==1 or not hasattr(stream,'mini'):continue
            def send(kind,payload=b''):
                stream.serial+=1
                hdr=struct.pack('<HIB',kind,len(payload),0) if stream.mini else struct.pack('<QHIIB',stream.serial,kind,len(payload),0,0)
                stream.sendall(hdr+payload)
            while stream.message_ready(stream.mini):
                kind,_,payload=read_main_message(stream,stream.mini)
                if kind==3:
                    if len(payload)!=8:raise p.ProtocolError('桌面 ACK 设置长度异常')
                    generation,stream.ack_window=struct.unpack('<II',payload)
                    stream.ack_count=0;send(1,struct.pack('<I',generation))
                    continue
                elif kind==4:
                    if len(payload)<12:raise p.ProtocolError('桌面 PING 长度异常')
                    send(3,payload[:12])
                elif link==2 and kind>=101:
                    self.result['displayMessageReceived']=True
                    stream.accept_display(kind,payload)
                if stream.ack_window:
                    stream.ack_count+=1
                    if stream.ack_count>=stream.ack_window:send(2);stream.ack_count=0

    def accept_display(self,kind,payload):
        """Require a created surface, matching H264 stream and complete frame."""
        if kind==314:
            if len(payload)!=20:raise p.ProtocolError('桌面表面消息长度异常')
            surface,width,height,_,_=struct.unpack('<IIIII',payload)
            if not 0<width<=16384 or not 0<height<=16384:raise p.ProtocolError('桌面表面尺寸异常')
            if not hasattr(self,'surfaces'):self.surfaces=set()
            self.surfaces.add(surface);self.result['desktopSurfaceCreated']=True
        elif kind==122:
            if len(payload)!=51:raise p.ProtocolError('桌面视频流消息长度异常')
            surface,stream_id,flags,codec=struct.unpack_from('<IIBB',payload)
            if not hasattr(self,'video_streams'):self.video_streams={}
            self.video_streams[stream_id]=(surface,codec)
            self.result['desktopVideoStreamCreated']=True
        elif kind==123:
            if len(payload)<12:raise p.ProtocolError('桌面视频帧被截断')
            stream_id,_,size=struct.unpack_from('<III',payload)
            if not size or size!=len(payload)-12:raise p.ProtocolError('桌面视频帧长度异常')
            surface,codec=getattr(self,'video_streams',{}).get(stream_id,(None,None))
            if surface not in getattr(self,'surfaces',set()) or codec!=2:return
            data=payload[12:];prefix=4 if data.startswith(b'\0\0\0\1') else 3 if data.startswith(b'\0\0\1') else 0
            if not prefix or len(data)<=prefix or not 1<=(data[prefix]&31)<=23:return
            self.result.update(desktopFrameReceived=True,desktopSessionEntered=True)

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
        stream=IceStream(tunnel,directory,result);stream.route=route
        main_channel(stream,options,serial,directory,result,on_connected,hold_seconds)

def run_gateway(machine,options,directory,ice=True,on_connected=None,hold_seconds=0,pin=None,authenticate=True,desktop=False):
    options=dict(options,_guest_user=machine.get('adUser'),_guest_password=machine.get('adPassword'))
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
