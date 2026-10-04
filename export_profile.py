"""Extract CEM constants from this sample's Blutter object pool, offline."""
import argparse,json,pathlib,re

HERE=pathlib.Path(__file__).resolve().parent

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pool',type=pathlib.Path,default=HERE.parent/'evidence/blutter/pp.txt')
    ap.add_argument('--output',type=pathlib.Path,default=HERE/'sample-profile.json')
    args=ap.parse_args()
    if not args.pool.is_file():ap.error('对象池文件不存在，请用 --pool 指定 Blutter pp.txt')
    pool=args.pool.read_text(encoding='utf-8')
    def value(offset):
        match=re.search(r'^\[pp\+'+re.escape(offset)+r'\] String: (".*")$',pool,re.M)
        if not match:raise ValueError('Missing object pool entry '+offset)
        return json.loads(match.group(1))
    profile={
        'sample_sha256':'81bc0d8d3675e095b4bb14756136fc93525acd21d281e7f634c6d921b899e8d4',
        'base_url':'https://cloudpc.ecloud.10086.cn',
        'access_key':value('0xbd50'),'signature_secret':value('0xbd58'),
        'rsa_private_pem':value('0xbce8'),'rsa_public_pem':value('0xbcf0')}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(profile,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Exported '+str(args.output)+'; no network requests.')

if __name__=='__main__':main()
