"""Observe TLS of one returned own-account CAG; sends no HTTP/account data."""
import argparse,hashlib,json,pathlib,socket,ssl
from urllib.parse import urlsplit
from cryptography import x509
import zte_connection as z


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--devices',type=pathlib.Path,help='本人的设备列表JSON')
    ap.add_argument('--machine-id',help='本人列表中的目标ID；默认读取本地配置target')
    ap.add_argument('--output-dir',type=pathlib.Path,default=z.p.DATA_DIR/'live')
    args=ap.parse_args()
    devices=args.devices
    if devices is None:
        for name in ('live/web-devices.local.json','live/sms-devices.local.json','devices.local.json'):
            if (z.p.DATA_DIR/name).is_file():devices=z.p.DATA_DIR/name;break
    if devices is None or not devices.is_file():ap.error('请用 --devices 提供本人设备列表')
    target=args.machine_id
    if not target:
        config=z.p.DATA_DIR/'account.local.json'
        if config.is_file():target=z.p.load_json(config).get('target',{}).get('machineId')
    if not target:ap.error('请用 --machine-id 或本地配置指定本人目标')
    matches=[m for m in z.p.load_json(devices)['body']['machineList'] if m.get('machineId')==target and m.get('originCompanyCode')=='ZTE']
    if len(matches)!=1:ap.error('本人列表中没有唯一对应的ZTE目标')
    key,lang=z.sdk_values()
    url,_,_=z.request_spec(matches[0],key,lang)
    u=urlsplit(url)
    if u.scheme!='https':ap.error('目标CAG不是HTTPS，不能检查TLS证书')
    output=args.output_dir;output.mkdir(parents=True,exist_ok=True)
    out={}
    try:
        with socket.create_connection((u.hostname,u.port or 443),timeout=10) as raw:
            with ssl.create_default_context().wrap_socket(raw,server_hostname=u.hostname):
                out['defaultTlsVerified']=True
    except ssl.SSLCertVerificationError as exc:
        out.update(defaultTlsVerified=False,verificationCode=exc.verify_code,verificationReason=exc.verify_message)
    except (ssl.SSLError,OSError) as exc:
        out.update(defaultTlsVerified=False,errorType=type(exc).__name__)
    # Observation only; this does not establish the gateway's identity.
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
    try:
        with socket.create_connection((u.hostname,u.port or 443),timeout=10) as raw:
            with ctx.wrap_socket(raw,server_hostname=u.hostname) as conn:
                der=conn.getpeercert(binary_form=True)
                cert=x509.load_der_x509_certificate(der)
                (output/'zte-cag-peer.der').write_bytes(der)
                z.p.save_json(output/'zte-cag-pin.local.json',{'url':url,'sha256':hashlib.sha256(der).hexdigest()})
                out.update(peerCertificateSaved=True,TLS=conn.version(),
                    validBefore=str(cert.not_valid_after_utc),validAfter=str(cert.not_valid_before_utc),
                    selfSigned=cert.issuer==cert.subject)
    except (ssl.SSLError,OSError) as exc:out['inspectionErrorType']=type(exc).__name__
    z.p.save_json(output/'zte-tls-result.local.json',out)
    print(json.dumps(out,ensure_ascii=False))
    return 0 if out.get('peerCertificateSaved') else 1

if __name__=='__main__':raise SystemExit(main())
