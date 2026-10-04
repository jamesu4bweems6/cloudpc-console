"""One native ZTE connection-parameter request for the configured own desktop.

No desktop session, renew loop, power operation, or arbitrary URL input.
"""
import base64, datetime as dt, ipaddress, json, pathlib, re, sys, ssl
from urllib.parse import urlsplit
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import cloudpc_protocol as p

HERE=pathlib.Path(__file__).parent

class PinnedGatewayAdapter(requests.adapters.HTTPAdapter):
    """Use the locally observed certificate only for the exact returned CAG URL.

    This is a local first-observation pin, not a public-CA validation claim.
    """
    def __init__(self,url,fingerprint):
        self.allowed_url=url
        self.fingerprint=fingerprint
        super().__init__(max_retries=0)

    def init_poolmanager(self,*args,**kwargs):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname=False
        context.verify_mode=ssl.CERT_NONE
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.maximum_version=ssl.TLSVersion.TLSv1_2
        kwargs.update(ssl_context=context,assert_fingerprint=self.fingerprint,
                      cert_reqs=ssl.CERT_NONE,assert_hostname=False)
        return super().init_poolmanager(*args,**kwargs)

    def cert_verify(self,conn,url,verify,cert):
        if url!=self.allowed_url or not conn.assert_fingerprint:
            raise p.ProtocolError('证书固定范围不匹配')
        conn.cert_reqs=ssl.CERT_NONE
        conn.ca_certs=None
        conn.ca_cert_dir=None

def sdk_values():
    # Exported once from AESEncode!0x11cdb00; runtime needs no IPA/SDK.
    profile=p.load_json(HERE/'zte-sample-profile.json')
    key=bytes.fromhex(profile['aes128KeyHex'])
    if len(key)!=16 or profile['language']!='zh':
        raise p.ProtocolError('样本 AES 常量不匹配')
    return key,profile['language']

def styled(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,indent=3,separators=(',', ' : '))+'\n'

def encode_param(value,key):
    raw=styled(value).encode('utf-8')
    if len(raw)>256:
        raise p.ProtocolError('输入超过样本 AES 包装长度，停止')
    pad=PKCS7(128).padder(); plain=pad.update(raw)+pad.finalize()
    enc=Cipher(algorithms.AES(key),modes.ECB()).encryptor()
    return base64.b64encode(enc.update(plain)+enc.finalize()).decode('ascii')

def request_spec(machine,key,language):
    c=machine.get('customLoginParams') or {}
    raw=c.get('csapip')
    if not isinstance(raw,str) or '/' in raw or '@' in raw:
        raise p.ProtocolError('认证设备信息中的 csapip 格式不支持')
    parsed=urlsplit('//'+raw)
    host=parsed.hostname
    if not host or parsed.port is None:
        raise p.ProtocolError('csapip 缺少主机或端口')
    # ParseSuOpercustomLoginParams!0x11b9840 forces TLS selector to 1.
    # encry at +0x6c is a separate response encryption flag, not TLS.
    scheme='https'
    cags=c.get('cagList') or []
    net_type=0 if not cags else 1
    headers={'Content-Type':'application/xml'}
    authority=parsed.netloc
    if cags:
        # DoSlectCagGateway selects a returned gateway; this experiment uses
        # the first, with no enumeration or port probing.
        gateway=cags[0]
        addr=gateway.get('addr')
        if not isinstance(addr,str) or not addr or any(ch in addr for ch in '/@:'):
            raise p.ProtocolError('暂不支持该 CAG 地址格式')
        port=int(gateway['port'])
        if not 1<=port<=65535:
            raise p.ProtocolError('CAG 端口无效')
        authority=f'{addr}:{port}'
        # DoGetSuOperConnectStr!0x11bed2c..0x11bed70.
        headers['X-Ap-sHost']=parsed.netloc
    inner={'vmid':machine['machineId'],'timestamp':'','opType':3}
    body={'language':language,'param':encode_param(inner,key),'timestamp':'',
          'encrypt':7,'netType':net_type,'supportAsync':1}
    return f'{scheme}://{authority}/cs/cs_suOperDesktop.action',body,headers

def fetch_parameters(machine,directory):
    key,language=sdk_values()
    url,body,headers=request_spec(machine,key,language)
    directory.mkdir(parents=True,exist_ok=True)
    p.save_json(directory/'request.local.json',{'url':url,'body':body,'headers':headers})
    with requests.Session() as session:
        session.trust_env=False
        pin_file=p.DATA_DIR/'live/zte-cag-pin.local.json'
        if pin_file.exists():
            pin=p.load_json(pin_file)
            if pin['url']!=url:raise p.ProtocolError('本地证书固定主机与认证网关不匹配')
            session.mount(url,PinnedGatewayAdapter(url,pin['sha256']))
        response=session.post(url,data=styled(body).encode('utf-8'),headers=headers,
                              timeout=(10,20),allow_redirects=False)
        (directory/'response.bin').write_bytes(response.content)
        if response.status_code!=200:raise p.ProtocolError('连接参数 HTTP 失败')
        decoded=response.json();p.save_json(directory/'response.local.json',decoded)
        if not isinstance(decoded,dict) or decoded.get('result') not in (0,'0') or decoded.get('success') is not True:
            raise p.ProtocolError('连接参数业务失败')
        return decoded

def main():
    config=p.load_json(p.DATA_DIR/'account.local.json')
    # Use only identifiers and hosts returned by the authenticated own account.
    devices=p.load_json(p.DATA_DIR/'live/sms-devices.local.json')['body']['machineList']
    selected=[m for m in devices if m.get('machineId')==config['target'].get('machineId')]
    if len(selected)!=1 or selected[0].get('originCompanyCode')!='ZTE':
        raise p.ProtocolError('需要匹配本人配置的唯一 ZTE 云电脑')
    key,language=sdk_values()
    url,body,headers=request_spec(selected[0],key,language)
    directory=p.DATA_DIR/'live'/dt.datetime.now().strftime('%Y%m%d-%H%M%S-%f-zte-parameters')
    directory.mkdir(parents=True)
    p.save_json(directory/'request.local.json',{'url':url,'body':body,'headers':headers})
    result={'stage':'zte-connection-parameters','desktopProtocolConnected':False,
            'expiryRenewalVerified':False}
    try:
        session=requests.Session()
        session.trust_env=False
        pin_file=p.DATA_DIR/'live/zte-cag-pin.local.json'
        if pin_file.exists():
            pin=p.load_json(pin_file)
            if pin['url']!=url:
                raise p.ProtocolError('本地证书固定主机与认证网关不匹配')
            session.mount(url,PinnedGatewayAdapter(url,pin['sha256']))
            result['tlsValidation']='exact_gateway_first_observation_sha256_pin'
        response=session.post(url,data=styled(body).encode('utf-8'),
                              headers=headers,timeout=(10,20),allow_redirects=False)
        (directory/'response.bin').write_bytes(response.content)
        result.update(httpStatus=response.status_code,responseBytes=len(response.content))
        try:
            decoded=response.json(); p.save_json(directory/'response.local.json',decoded)
            result['responseKeys']=sorted(decoded) if isinstance(decoded,dict) else []
            if isinstance(decoded,dict):
                code=decoded.get('result')
                result['resultCode']=int(code) if isinstance(code,(int,str)) and re.fullmatch(r'-?\d{1,8}',str(code)) else None
                result['connectStrPresent']=bool(decoded.get('connectStr'))
        except (ValueError,TypeError):
            result['jsonResponse']=False
    except requests.RequestException as exc:
        result['errorType']=type(exc).__name__
    p.save_json(directory/'result.local.json',result)
    print(json.dumps(result,ensure_ascii=False))
    print('完整连接响应仅保存本地: '+str(directory))

if __name__=='__main__':
    try:main()
    except (p.ProtocolError,KeyError,ValueError) as exc:
        print('未发送请求: '+type(exc).__name__)
        sys.exit(1)
