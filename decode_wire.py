"""Decode saved ZTE reply headers without printing keys, IDs or guest data."""
import argparse,json,pathlib,struct
import zte_gateway_probe as g
import cloudpc_protocol as p

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('kind',choices=['link-reply','main'])
    ap.add_argument('path',type=pathlib.Path)
    args=ap.parse_args();raw=args.path.read_bytes()
    if args.kind=='link-reply':
        magic,major,minor,size=struct.unpack('<4sIII',raw[:16])
        if magic!=b'REDQ' or size!=len(raw)-16:raise p.ProtocolError('REDQ 大小不符')
        common,channel=g.link_capabilities(raw[16:])
        result={'magic':'REDQ','major':major,'minor':minor,'bodySize':size,
                'error':struct.unpack_from('<I',raw,16)[0],
                'commonCaps':[hex(x) for x in common],'channelCaps':[hex(x) for x in channel]}
    else:
        _,kind,size,_,flags=struct.unpack('<QHIIB',raw[:19])
        if size!=len(raw)-19:raise p.ProtocolError('主通道消息大小不符')
        result={'type':kind,'payloadSize':size,'flags':flags,'nativeHeaderSize':19}
    print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__':main()
