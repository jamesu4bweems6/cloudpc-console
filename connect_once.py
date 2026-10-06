"""One real ZTE ICE connection with fresh parameters and connected CEM reports."""
import argparse,json,pathlib,sys,datetime as dt
import requests
import cloudpc_protocol as p
import zte_connection as z
import zte_gateway_probe as g
from live_validate import LocalAuditTransport,timestamp

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--config',type=pathlib.Path,default=p.DATA_DIR/'account.local.json')
    ap.add_argument('--session',type=pathlib.Path,default=p.DATA_DIR/'session.local.json')
    ap.add_argument('--hold-seconds',type=int,default=15,choices=range(5,61),metavar='5..60')
    args=ap.parse_args()
    config=p.load_json(args.config)
    state=p.load_json(args.session)
    if state.get('deviceUid')!=config['common']['deviceUid']:
        raise p.ProtocolError('会话与本地设备身份不一致，请重新登录')
    p.ensure_gateway_pins()
    directory=p.DATA_DIR/'live'/(timestamp()+'-connect-once');directory.mkdir(parents=True)
    result={'stage':'connect-once','startedAt':dt.datetime.now(dt.timezone.utc).isoformat(),
            'success':False,'desktopProtocolConnected':False,'expiryRenewalVerified':False}
    client=p.Client(p.load_json(p.HERE/'sample-profile.json'),config,state,
                    transport=LocalAuditTransport(directory),audit_dir=directory)
    phase='session_prepare'
    try:
        devices=client.prepare_session(client.devices, on_recovery=lambda status:
            print(json.dumps({'stage':'session-recovery','status':status}),flush=True))
        p.save_json(args.session,client.state)
        result['ticketRefreshAccepted']=True
        if client.state.get('pendingConnectId'):
            phase='pending_disconnect'
            client.session_status(client.state['pendingConnectId'],False)
            client.state.pop('pendingConnectId')
        phase='target_selection'
        matches=[m for m in devices['body']['machineList'] if m.get('machineId')==config['target'].get('machineId')]
        if len(matches)!=1 or matches[0].get('originCompanyCode')!='ZTE':
            raise p.ProtocolError('仅支持本人配置的唯一 ZTE 桌面')
        machine=matches[0]
        p.save_json(directory/'devices.local.json',devices)
        phase='snapshot_before';p.save_json(directory/'before.local.json',client.snapshot(config['target']))
        phase='session_registration';client.record_device();client.session_status()
        phase='connection_parameters'
        value=z.fetch_parameters(machine,directory/'parameters')
        phase='parameter_decode'
        options=g.connection_options(machine,value)
        phase='ice_pin_check'
        pin_file=p.DATA_DIR/'live/zte-ice-pin.local.json'
        if not pin_file.exists():
            raise p.ConnectionError('ICE_PIN_MISSING')
        pin=p.load_json(pin_file)
        def connected():
            connect_id=client.machine_connected(machine)
            p.save_json(args.session,client.state)
            client.session_status(connect_id,True)
            result['connectedReportAccepted']=True
            print('桌面认证成功，在线连接上报已接受。',flush=True)
        phase='desktop_channel'
        result.update(g.run_gateway(machine,options,directory/'desktop',
                                   on_connected=connected,hold_seconds=args.hold_seconds,pin=pin))
        result['stage']='connect-once'
        result['success']=bool(result.get('controlSessionCompleted') and result.get('connectedReportAccepted'))
        if not result['success']:result['failedStage']=phase
        if str(result.get('errorCode'))=='401':client.state['authRequired']=True
    except (p.ProtocolError,requests.RequestException,OSError,ValueError,KeyError) as exc:
        result.update(errorType=getattr(exc,'error_type',type(exc).__name__),failedStage=phase)
        if isinstance(exc,(p.ConnectionError,p.AuthenticationRequired)):result['diagnosticCode']=exc.diagnostic_code
        if isinstance(exc,(p.BusinessError,p.AuthenticationRequired)):
            result['errorCode']=exc.code
            if exc.code=='401' or isinstance(exc,p.AuthenticationRequired):client.state['authRequired']=True
    finally:
        pending=client.state.get('pendingConnectId')
        if pending:
            try:
                client.session_status(pending,False)
                client.state.pop('pendingConnectId',None)
                result['disconnectedReportAccepted']=True
            except p.ProtocolError as exc:
                result.update(cleanupErrorType=type(exc).__name__,success=False)
                if isinstance(exc,p.BusinessError) and exc.code=='401':
                    client.state['authRequired']=True;result['errorCode']=exc.code
        try:p.save_json(directory/'after.local.json',client.snapshot(config['target']))
        except p.ProtocolError:result['afterSnapshotFailed']=True
        p.save_json(args.session,client.state)
        result.update(sessionRecoveryAttempted=client.session_recovery_attempted,
                      sessionRecovered=client.session_recovered,
                      authenticationRequired=bool(client.state.get('authRequired')))
        result['finishedAt']=dt.datetime.now(dt.timezone.utc).isoformat()
        p.save_json(directory/'result.local.json',result)
        print(json.dumps(result,ensure_ascii=False))
        print('本地结果目录: '+str(directory))
    return 0 if result['success'] else 1

if __name__=='__main__':sys.exit(main())
