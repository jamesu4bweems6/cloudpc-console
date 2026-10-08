"""Pure CEM HTTP protocol reconstructed from the supplied iOS AOT snapshot.

Static reconstruction; report-probe is an experiment, not proof of shutdown renewal.
No native SDK or app automation. Session preparation permits one password recovery on 401.
"""
from __future__ import annotations
import argparse
import base64
import datetime as dt
import getpass
import hashlib
import hmac
import json
import os
import pathlib
import sys
import uuid
from urllib.parse import quote

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

HERE = pathlib.Path(__file__).resolve().parent
DATA_DIR = pathlib.Path(os.environ.get('CLOUDPC_DATA_DIR', str(HERE))).resolve()
PREFIX = '/api/cem/gateway/outer/cem-webapi/'
BASE_URL = 'https://cloudpc.ecloud.10086.cn'

class ProtocolError(Exception):
    pass

CONNECTION_HINTS = {
    'GUEST_ENTRY_UNCONFIRMED': '收到桌面画面，但未确认 Windows 登录或解锁；本次不计为进入系统。',
    'GUEST_CREDENTIALS_MISSING': '来宾未登录且连接响应未提供完整来宾凭据。',
    'GUEST_AGENT_DISCONNECTED': '来宾代理已断开，未完成进入系统。',
    'DESKTOP_ENTRY_UNCONFIRMED': '仅完成通道认证，未收到有效桌面画面；本次不计为进入系统。',
    'GUEST_RSA_LINK_UNSUPPORTED': '网关要求尚未适配的 RSA2048 来宾登录扩展，已停止。',
    'DESKTOP_POWER_ON_REQUIRED': '云电脑已关机，请先开机后再连接。',
    'DESKTOP_PARAMETERS_PENDING': '桌面连接参数尚未就绪，请稍后再连接。',
    'AUTH_CREDENTIALS_REQUIRED': '登录票据已失效；未保存账号密码，请在网页重新登录。仅短信登录无法自动续登。',
    'AUTH_TRUST_REQUIRED': '自动续登需要设备可信短信验证，请点击密码登录并完成验证码验证。',
    'AUTH_TWO_FACTOR_REQUIRED': '自动续登需要双因素短信验证，请点击密码登录并完成验证码验证。',
    'AUTH_ACCOUNT_REQUIRED': '自动续登需要选择企业账号，请保存企业用户名后重新登录。',
    'CAG_TLS_NO_PIN': 'CAG HTTPS 握手失败，未配置 CAG 证书固定文件。请导入已核对的 zte-cag-pin.local.json。',
    'CAG_TLS_PINNED_FAILURE': '已配置 CAG 证书固定值，但 HTTPS 验证或握手失败。请核对证书是否变更及 TLS 兼容性。',
    'CAG_PIN_GATEWAY_MISMATCH': 'CAG 证书固定文件与本次返回的网关不匹配，请核对目标及固定文件。',
    'ICE_PIN_MISSING': '缺少 ICE 证书固定文件，请导入已核对的 zte-ice-pin.local.json。',
    'ICE_PIN_MISMATCH': 'ICE 证书与固定值不匹配，已停止连接；请重新核对网关证书。',
    'ICE_PIN_GATEWAY_MISMATCH': 'ICE 证书固定文件与本次返回的网关不匹配，请核对目标及固定文件。',
}

class ConnectionError(ProtocolError):
    def __init__(self, diagnostic_code, error_type=None):
        self.diagnostic_code = diagnostic_code
        self.error_type = error_type or type(self).__name__
        super().__init__(CONNECTION_HINTS[diagnostic_code])

def connection_failure_message(result):
    """Only fixed labels; never expose raw transport exception text or URLs."""
    result = result or {}
    hint = CONNECTION_HINTS.get(result.get('diagnosticCode'))
    if hint:return hint
    if str(result.get('errorCode')) == '401':return '登录会话已失效，请重新登录。'
    if result.get('errorType') == 'SSLError':
        return ('ICE TLS 验证或握手失败，请核对 ICE 固定证书。' if result.get('gatewayAuthenticated') else
                'CAG HTTPS 验证或握手失败，请检查 CAG 固定证书及 TLS 配置。')
    if result.get('errorCode'):return '业务码 '+str(result['errorCode'])
    return '请查看最近记录中的错误类型和失败阶段。'

class BusinessError(ProtocolError):
    def __init__(self, code, response):
        # Keep messages/bodies local: a server error can echo credentials.
        self.code, self.response = str(code), response
        label = {'30002009': '需要设备可信验证', '30002060': '需要双因素验证',
                 '10002034': '需要选择企业账号', '30001004': '需要客户端提示验证'}.get(self.code, '业务请求失败')
        super().__init__(f'{label} (errorCode={self.code})')

class AuthenticationRequired(ProtocolError):
    def __init__(self, diagnostic_code, code='401'):
        self.diagnostic_code, self.code = diagnostic_code, str(code)
        self.error_type = 'BusinessError'
        super().__init__(CONNECTION_HINTS[diagnostic_code])

def dumps(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)

def utc8_timestamp(now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise ValueError('now must be timezone-aware')
    # The app adds 8 h to UTC and prints a literal Z; reproduce that convention.
    return (now.astimezone(dt.timezone.utc) + dt.timedelta(hours=8)).strftime('%Y-%m-%dT%H:%M:%SZ')

def component(value):
    return quote(str(value), safe="-_.!~*'()", encoding='utf-8', errors='strict')

def percent_encode(value):
    return component(value).replace('+', '%20').replace('*', '%2A').replace('%7E', '~')

def signed_path(path, profile, *, timestamp=None, nonce=None, method='POST'):
    if not path.startswith(PREFIX) or '?' in path or '#' in path:
        raise ProtocolError('Only reconstructed CEM paths are supported')
    fields = {'AccessKey': profile['access_key'], 'Timestamp': timestamp or utc8_timestamp(),
              'SignatureMethod': 'HmacSHA1', 'SignatureVersion': 'V2.0',
              'SignatureNonce': nonce or uuid.uuid4().hex}
    query = '&'.join(component(k) + '=' + component(fields[k]) for k in sorted(fields))
    text = method.upper() + '\n' + percent_encode(path) + '\n' + hashlib.sha256(query.encode('utf-8')).hexdigest()
    key = ('BC_SIGNATURE&' + profile['signature_secret']).encode('utf-8')
    signature = hmac.new(key, text.encode('utf-8'), hashlib.sha1).hexdigest()
    return path + '?' + query + '&Signature=' + percent_encode(signature)

class Envelope:
    def __init__(self, profile):
        self.public = serialization.load_pem_public_key(profile['rsa_public_pem'].encode('ascii'))
        self.private = serialization.load_pem_private_key(profile['rsa_private_pem'].encode('ascii'), password=None)
        if self.public.key_size != 1024 or self.public.public_numbers() != self.private.public_key().public_numbers():
            raise ProtocolError('Unexpected sample RSA key pair')

    def encode_bytes(self, raw):
        blocks = [self.public.encrypt(raw[i:i + 117], padding.PKCS1v15()) for i in range(0, len(raw), 117)]
        return base64.b64encode(b''.join(blocks)).decode('ascii')

    def decode_bytes(self, encoded):
        raw = base64.b64decode(encoded, validate=True)
        if not raw or len(raw) % 128:
            raise ProtocolError('RSA response must contain complete 128-byte blocks')
        return b''.join(self.private.decrypt(raw[i:i + 128], padding.PKCS1v15()) for i in range(0, len(raw), 128))

    def wrap(self, data):
        return {'params': self.encode_bytes(dumps(data).encode('utf-8'))}

    def unwrap(self, value):
        if isinstance(value, str):
            value = json.loads(value)
        if not isinstance(value, dict):
            raise ProtocolError('Response is not a JSON object')
        if 'params' in value:
            value = json.loads(self.decode_bytes(value['params']).decode('utf-8'))
        if not isinstance(value, dict):
            raise ProtocolError('Decoded response is not a JSON object')
        return value

def load_json(path):
    return json.loads(pathlib.Path(path).read_text(encoding='utf-8-sig'))

def save_json(path, value):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)

def ensure_gateway_pins(data_dir=None):
    """Seed bundled pins only when missing; never replace a user's existing pin."""
    data_dir = pathlib.Path(data_dir) if data_dir is not None else DATA_DIR
    created = []
    for name in ('zte-cag-pin', 'zte-ice-pin'):
        source = HERE / 'gateway-pins' / (name + '.json')
        destination = data_dir / 'live' / (name + '.local.json')
        if destination.exists() or not source.is_file():continue
        value = load_json(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            with destination.open('x', encoding='utf-8') as file:
                file.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
        except FileExistsError:continue
        created.append(name)
    return created

class Client:
    def __init__(self, profile, config, session=None, *, transport=None, audit_dir=None):
        if profile['base_url'] != BASE_URL:
            raise ProtocolError('Unexpected service origin in sample profile')
        self.profile, self.config = profile, config
        self.state = dict(session or {})
        self.envelope = Envelope(profile)
        self.transport = transport or requests.Session()
        self.audit_dir = pathlib.Path(audit_dir) if audit_dir else None
        self.count = 0
        self.session_recovery_attempted = False
        self.session_recovered = False
        self.common = dict(config['common'])
        for field in ('deviceUid', 'deviceName', 'clientVersion', 'deviceModel', 'operatingVersion'):
            if not self.common.get(field):
                raise ProtocolError('请在本地配置中填写 common.' + field)

    def post(self, endpoint, data, *, allow_codes=()):
        body = dict(data)
        for k, v in self.common.items():
            body.setdefault(k, v)
        path = PREFIX + endpoint
        wrapped = self.envelope.wrap(body)
        url = BASE_URL + signed_path(path, self.profile)
        self.count += 1
        try:
            response = self.transport.post(url, data=dumps(wrapped).encode('utf-8'),
                headers={'Content-Type': 'application/json;charset=uTF-8'},
                timeout=(10, 30), allow_redirects=False)
        except requests.RequestException:
            raise ProtocolError('网络请求失败；未自动重试，请检查本机网络') from None
        if response.status_code != 200:
            raise ProtocolError(f'HTTP状态异常: {response.status_code}')
        try:
            decoded = self.envelope.unwrap(response.json())
        except (ValueError, TypeError, KeyError):
            raise ProtocolError('响应解密/JSON结构异常') from None
        if self.audit_dir:
            save_json(self.audit_dir / f'{self.count:03d}-{endpoint.replace("/", "-")}.json', decoded)
        code = decoded.get('errorCode')
        if code != '200' and str(code) not in allow_codes:
            raise BusinessError(code, decoded)
        return decoded

    @property
    def token(self):
        if not self.state.get('accessToken'):
            raise ProtocolError('请先完成短信或密码登录')
        return self.state['accessToken']

    def device_system(self):
        return 'iOS_' + self.common['operatingVersion']

    def send_sms(self, mobile, code_type='login'):
        return self.post('login/sendVerifySms', {'mobile': mobile, 'codeType': code_type,
                         'accessToken': self.state.get('accessToken')})

    def verify_sms(self, mobile, code):
        c = self.common
        return self.post('login/verifySms', {'mobile': mobile, 'verificationCode': code,
            'clientType': 'mobile_ios', 'deviceUid': c['deviceUid'], 'deviceName': c['deviceName'],
            'deviceSystem': self.device_system(), 'clientVersion': c['clientVersion'],
            'deviceModel': c['deviceModel'], 'isNeedTemporaryDeviceSelection': True},
            allow_codes=('10002034',))

    def verify_password(self, username, password):
        c = self.common
        return self.post('login/verify', {'username': username, 'password': password,
            'deviceName': c['deviceName'], 'timestamp': utc8_timestamp(), 'clientType': 'mobile_ios',
            'deviceUid': c['deviceUid'], 'clientVersion': c['clientVersion'],
            'deviceSystem': self.device_system(), 'companyCode': 'ECloud', 'deviceType': 'mobile',
            'deviceModel': c['deviceModel'], 'clientNeedTwoFactor': True},
            allow_codes=('10002034', '30002060', '30002009'))

    def verify_two_factor(self, challenge, username, password, mobile, code):
        return self.post('login/verifyTwoFactorAuthSms', {'mobile': mobile, 'userName': username,
            'verificationCode': code, 'password': password, 'deviceSystem': self.device_system(),
            'source': None, 'code': challenge.get('code'), 'refreshCode': challenge.get('refreshCode')})

    def trust_device(self, challenge, mobile, code, username):
        c = self.common
        return self.post('login/trustDevice', {'accessToken': self.state.get('accessToken'),
            'mobile': mobile, 'verificationCode': code, 'clientType': 'mobile_ios',
            'deviceUid': c['deviceUid'], 'deviceName': c['deviceName'],
            'code': challenge.get('code'), 'refreshCode': challenge.get('refreshCode'),
            'loginUserName': username})

    def login_by_code(self, username, challenge):
        return self.post('login/loginByCode', {'username': username, 'code': challenge.get('code'),
                                            'refreshCode': None, 'source': None})

    def finish_login(self, response, *, selected_username=None, temporary=True):
        body = response.get('body')
        if not isinstance(body, dict):
            raise ProtocolError('登录响应缺少 body')
        if response.get('errorCode') == '10002034':
            if not selected_username:
                raise ProtocolError('需要企业账号选择；请填写 auth.selected_username 后重新登录')
            response = self.login_by_code(selected_username, body)
            body = response.get('body') or {}
        if response.get('errorCode') != '200':
            raise BusinessError(response.get('errorCode'), response)
        ticket = body.get('accessTicket')
        if not ticket:
            raise ProtocolError('登录响应未返回 accessTicket；没有继续上报')
        if body.get('isCurrentDeviceTrustBeforeLogin') is False:
            # Native UI offers temporary device selection. 1 means temporary, 0 trusted.
            self.post('login/trustOrTemporaryDevice', {'accessTicket': ticket,
                'isTemporary': 1 if temporary else 0, 'clientType': 'mobile_ios',
                'deviceUid': self.common['deviceUid'], 'deviceName': self.common['deviceName']})
        result = self.post('login/verifyAccessTicket', {'accessTicket': ticket})
        token_body = result.get('body') or {}
        if not token_body.get('accessToken'):
            raise ProtocolError('票据交换未返回 accessToken')
        self.state = {'accessTicket': ticket, 'accessToken': token_body['accessToken'],
            'clientLoginUid': str(uuid.uuid4()), 'deviceUid': self.common['deviceUid'],
            'loggedInAt': dt.datetime.now(dt.timezone.utc).isoformat()}
        return result

    def devices(self):
        return self.post('user/getDeviceInfo', {'accessToken': self.token, 'allCompany': True, 'version': '1.0.0'})

    def refresh_ticket(self):
        # App getCemTokenByCemTicket!0x484a8c, interceptor!0x932824.
        ticket=self.state.get('accessTicket')
        if not ticket:raise ProtocolError('缺少登录票据，请重新登录')
        result=self.post('login/verifyAccessTicket',{'accessTicket':ticket})
        token=(result.get('body') or {}).get('accessToken')
        if not token:raise ProtocolError('刷新票据未返回 token')
        self.state['accessToken']=token
        self.state['tokenRefreshedAt']=dt.datetime.now(dt.timezone.utc).isoformat()
        return result

    def prepare_session(self, read=None, on_recovery=None):
        """Refresh then optionally read; recover once on 401 before desktop actions.

        The callback must be a read-only operation. Never retry connection reports,
        desktop handshakes, network failures, or SMS verification here.
        """
        if self.state.get('deviceUid') != self.common['deviceUid']:
            raise ProtocolError('会话与本地设备身份不一致，请重新登录')
        try:
            self.refresh_ticket()
            value = read() if read else None
        except BusinessError as exc:
            if exc.code != '401':raise
            self.state['authRequired'] = True
            self.session_recovery_attempted = True
            if on_recovery:on_recovery('started')
            auth = self.config.get('auth', {})
            if not auth.get('username') or not auth.get('password'):
                raise AuthenticationRequired('AUTH_CREDENTIALS_REQUIRED') from None
            response = self.verify_password(auth['username'], auth['password'])
            code = str(response.get('errorCode'))
            hints = {'30002009':'AUTH_TRUST_REQUIRED', '30002060':'AUTH_TWO_FACTOR_REQUIRED'}
            if code in hints:raise AuthenticationRequired(hints[code], code)
            if code == '10002034' and not auth.get('selected_username'):
                raise AuthenticationRequired('AUTH_ACCOUNT_REQUIRED', code)
            # Keep unfinished disconnect identity until its cleanup succeeds.
            pending = {k:self.state[k] for k in ('pendingConnectId','loginUid') if k in self.state}
            self.finish_login(response, selected_username=auth.get('selected_username'))
            if pending.get('pendingConnectId'):self.state.update(pending)
            self.session_recovered = True
            if on_recovery:on_recovery('success')
            try:value = read() if read else None
            except BusinessError as retry_error:
                if retry_error.code == '401':self.state['authRequired'] = True
                raise
        self.state.pop('authRequired', None)
        return value

    def record_device(self):
        data = {'accessToken': self.token, 'deviceUid': self.common['deviceUid'],
            'clientType': self.common['clientType'], 'deviceSystem': self.device_system()}
        for k in ('clientVersion', 'deviceModel', 'ipAddress', 'macAddress', 'deviceCompany',
                  'processor', 'ram', 'diskUsed', 'diskTotal', 'operatingSystem',
                  'operatingVersion', 'deviceType', 'companyCode', 'deviceName'):
            data[k] = self.common.get(k)
        data['clientLoginUid'] = self.state['clientLoginUid']
        result = self.post('login/recordDeviceInfo', data)
        login_uid = (result.get('body') or {}).get('loginUid')
        if not login_uid:
            raise ProtocolError('设备上报缺少 loginUid；没有继续连接上报')
        self.state['loginUid'] = login_uid
        return result

    def session_status(self, connect_id=None, connected=False):
        if not self.state.get('loginUid'):
            raise ProtocolError('缺少 loginUid')
        return self.post('session/updateSessionStatus', {'accessToken': self.token,
            # A connected desktop forces 0. On disconnect, a foreground logged-in
            # app retains its login state (also 0), rather than entering state 3.
            'loginUid': self.state['loginUid'], 'loginStatus': '0',
            'connectList': [{'connectId': connect_id, 'connectStatus': connected}] if connect_id else []})

    def report_probe(self, machine):
        """Test whether business reports alone renew expiry; does NOT open a desktop."""
        if not machine.get('machineId') or not machine.get('machineName'):
            raise ProtocolError('请从 devices 结果填写 target.machineId 和 target.machineName')
        self.record_device()
        # reportSessionStatus (App!0xb533f4) registers the foreground login
        # after recordDeviceInfo, before any machine connection report.
        self.session_status()
        connect_id = self.machine_connected(machine)
        try:
            self.session_status(connect_id, True)
        finally:
            self.session_status(connect_id, False)
            self.state.pop('pendingConnectId', None)
        return {'reportAccepted': True, 'expiryRenewalVerified': False, 'desktopProtocolConnected': False}

    def machine_connected(self, machine):
        """Call only after a real desktop connection (or explicit report-probe)."""
        result = self.post('session/machineConnect', {'ticket': self.state['accessTicket'],
            'accessToken': self.token, 'machineId': machine['machineId'], 'machineName': machine['machineName'],
            'status': 'success', 'flag': True, 'errorCode': machine.get('connectErrorCode', ''),
            'errorMsg': machine.get('connectErrorMsg', ''), 'clientConnectId': str(uuid.uuid4()),
            'clientLoginUid': self.state['clientLoginUid']})
        connect_id = (result.get('body') or {}).get('connectId')
        if not connect_id:
            raise ProtocolError('连接上报缺少 connectId；没有继续状态上报')
        self.state['pendingConnectId'] = connect_id
        return connect_id

    def snapshot(self, target):
        ids = [target['machineId']] if target.get('machineId') else []
        pools = [target['resourcePoolUid']] if target.get('resourcePoolUid') else []
        policy = self.post('user/getUserDevicePolicy/v2', {'accessToken': self.token,
                          'machineIds': ids, 'resourcePoolUidList': pools})
        instances = [target['instanceId']] if target.get('instanceId') else []
        status = self.post('user/getDesktopStatus', {'accessToken': self.token,
                          'instanceIdList': instances, 'resourcePoolUidList': pools})
        return {'observedAt': dt.datetime.now(dt.timezone.utc).isoformat(), 'policy': policy, 'status': status}

    def power_on(self, machine):
        """Only power on the exact configured own, nonpooled ZTE target."""
        if (machine.get('machineId') != self.config['target'].get('machineId') or
            machine.get('originCompanyCode') != 'ZTE' or machine.get('resourcePoolUid') or
            machine.get('machineStatus') != 'shutdown' or not machine.get('machineName')):
            raise ProtocolError('开机目标或状态不符合当前本人桌面')
        # Dart outer.dart::setMachineOperate!0x5eac84 maps powerOn to available.
        return self.post('resource/operate', {'accessToken':self.token, 'operate':'available',
            'machineId':machine['machineId'], 'machineName':machine['machineName'],
            'deviceUid':self.common['deviceUid'], 'sdkType':'1',
            'sdkVersion':'V1.2.260108'})

def init_config(path):
    path = pathlib.Path(path)
    if path.exists():
        raise ProtocolError('配置文件已存在，未覆盖')
    save_json(path, {'auth': {'mobile': '', 'username': '', 'password': '', 'selected_username': ''},
        'common': {'clientType': 'mobile_ios', 'deviceUid': str(uuid.uuid4()).upper(),
            'deviceName': 'ProtocolClient', 'companyCode': 'ECloud', 'clientVersion': '3.6.6', 'deviceType': 'mobile',
            'deviceModel': 'iPhone', 'deviceCompany': 'Apple', 'ipAddress': '', 'macAddress': '',
            'operatingSystem': 'iOS', 'operatingVersion': '18.0', 'processor': '', 'ram': '',
            'diskUsed': '', 'diskTotal': ''},
        'target': {'machineId': '', 'machineName': '', 'instanceId': '', 'resourcePoolUid': ''}})

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('init', 'sms-send', 'sms-login', 'password-login',
        'devices', 'snapshot', 'report-probe', 'close-report'))
    parser.add_argument('--config', type=pathlib.Path, default=DATA_DIR / 'account.local.json')
    parser.add_argument('--profile', type=pathlib.Path, default=HERE / 'sample-profile.json')
    parser.add_argument('--session', type=pathlib.Path, default=DATA_DIR / 'session.local.json')
    parser.add_argument('--output', type=pathlib.Path)
    parser.add_argument('--audit-dir', type=pathlib.Path, help='Optional sensitive decoded responses, saved locally')
    parser.add_argument('--send-sms', action='store_true', help='sms-login: request one SMS before prompting')
    args = parser.parse_args()
    if args.command == 'init':
        init_config(args.config)
        print('已创建本地配置；请填写账户和设备信息。未联网。')
        return
    config = load_json(args.config)
    state = load_json(args.session) if args.session.exists() else {}
    if state.get('deviceUid') and state['deviceUid'] != config['common']['deviceUid']:
        raise ProtocolError('session 与本地 deviceUid 不一致，请重新登录')
    client = Client(load_json(args.profile), config, state, audit_dir=args.audit_dir)
    auth = config['auth']
    try:
        if args.command.startswith('sms-'):
            mobile = auth.get('mobile') or input('手机号: ').strip()
            if args.command == 'sms-send' or args.send_sms:
                client.send_sms(mobile)
                print('验证码发送接口已接受请求。')
            if args.command == 'sms-login':
                code = getpass.getpass('短信验证码（不回显）: ').strip()
                result = client.verify_sms(mobile, code)
                client.finish_login(result, selected_username=auth.get('selected_username'))
                print('短信登录票据交换完成；会话已保存到本地。')
        elif args.command == 'password-login':
            username = auth.get('username') or input('账号: ').strip()
            password = auth.get('password') or getpass.getpass('密码（不回显）: ')
            result = client.verify_password(username, password)
            if result.get('errorCode') == '30002009':
                challenge = result.get('body') or {}
                mobile = auth.get('mobile') or challenge.get('mobile')
                if not mobile or '*' in mobile:
                    raise ProtocolError('设备验证需要在 auth.mobile 填写完整绑定手机号')
                client.send_sms(mobile, 'trust')
                code = getpass.getpass('设备验证短信验证码: ').strip()
                result = client.trust_device(challenge, mobile, code, username)
            if result.get('errorCode') == '30002060':
                challenge = result.get('body') or {}
                mobile = challenge.get('mobile') or auth.get('mobile')
                if not mobile or '*' in mobile:
                    raise ProtocolError('双因素验证需要在 auth.mobile 填写完整绑定手机号')
                client.send_sms(mobile, 'twoFactorAuth')
                code = getpass.getpass('双因素短信验证码: ').strip()
                result = client.verify_two_factor(challenge, username, password, mobile, code)
            client.finish_login(result, selected_username=auth.get('selected_username'))
            print('密码登录票据交换完成；会话已保存到本地。')
        elif args.command == 'devices':
            result = client.devices()
            dest = args.output or DATA_DIR / 'devices.local.json'
            save_json(dest, result)
            print(f'设备列表已保存到 {dest}；从中填写 target 字段。')
        elif args.command == 'snapshot':
            result = client.snapshot(config['target'])
            dest = args.output or DATA_DIR / 'snapshot.local.json'
            save_json(dest, result)
            print(f'策略和状态已保存到 {dest}。')
        elif args.command == 'report-probe':
            result = client.report_probe(config['target'])
            if args.output:
                save_json(args.output, result)
            print('连接及断开上报接口已接受请求；尚未证明延长关机期限，也未建立桌面协议连接。')
        elif args.command == 'close-report':
            cid = client.state.get('pendingConnectId')
            if not cid:
                raise ProtocolError('没有待关闭的连接上报')
            client.session_status(cid, False)
            client.state.pop('pendingConnectId')
            print('断开状态上报完成。')
    finally:
        if client.state.get('accessToken'):
            save_json(args.session, client.state)

if __name__ == '__main__':
    try:
        main()
    except (ProtocolError, OSError, ValueError, KeyError) as exc:
        print(f'错误: {exc}', file=sys.stderr)
        sys.exit(1)
