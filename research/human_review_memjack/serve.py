"""Local-only, two-rater source-first annotation. No model/GPU calls."""
import argparse,json,re,sys,threading,time,secrets,webbrowser
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit,parse_qs
from common import read,save,digest,validate_blind,validate_quality,STRATEGIES,QUALITY,verify_bundle
HERE=Path(__file__).resolve().parent

def lock_exclusive(handle):
 """Portable single-instance lock (Linux/macOS: flock, Windows: msvcrt)."""
 try:
  import fcntl;fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except ImportError:
  import msvcrt;msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--bundle',type=Path,required=True);ap.add_argument('--rater',choices=['A','B'],required=True);ap.add_argument('--port',type=int);ap.add_argument('--open',action='store_true',help='open the review page in your browser');a=ap.parse_args();bundle=a.bundle.resolve();verify_bundle(bundle);orders=read(bundle/'orders.json');order=orders[a.rater];mutex=threading.Lock()
 (bundle/'annotations'/a.rater).mkdir(parents=True,exist_ok=True)
 lock=(bundle/'annotations'/a.rater/'server.lock').open('a')
 try:lock_exclusive(lock)
 except OSError:sys.exit(f'Reviewer {a.rater} is already running for this bundle. Close the other window first, or reopen the address it printed.')
 token=secrets.token_urlsafe(24);token_path=bundle/'annotations'/a.rater/'access-token.txt';token_path.write_text(token);token_path.chmod(0o600)
 def record(rater,cid):return bundle/'annotations'/rater/(cid+'.json')
 def unlocked():
  release=bundle/'memory_unblind.release.json';reference=bundle/'reference.json'
  return all(record(r,c).exists() for r in ['A','B'] for c in orders[r]) and release.exists() and reference.exists() and read(release).get('reference_sha256')==__import__('common').file_sha(reference)
 class Handler(BaseHTTPRequestHandler):
  def log_message(self,*args):pass
  def send(self,data,status=200,kind='application/json'):
   raw=data if isinstance(data,bytes) else json.dumps(data,ensure_ascii=False).encode();self.send_response(status);self.send_header('Content-Type',kind);self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
  def cid(self,value):
   if value not in order or not re.fullmatch(r'case_[0-9a-f]{12}',value):raise ValueError('Unknown assigned case')
   return value
  def authorized(self):
   supplied=self.headers.get('X-Review-Token') or parse_qs(urlsplit(self.path).query).get('token',[''])[0]
   return secrets.compare_digest(supplied,token)
  def do_GET(self):
   try:
    path=urlsplit(self.path).path
    if path=='/':return self.send((HERE/'index.html').read_bytes(),kind='text/html; charset=utf-8')
    if path=='/guidelines':return self.send((HERE/'GUIDELINES_EN.md').read_bytes(),kind='text/plain; charset=utf-8')
    if not self.authorized():return self.send({'error':'Use the reviewer URL printed by the server, including its access fragment.'},403)
    if path=='/api/status':
     return self.send({'rater':a.rater,'order':order,'done_blind':[c for c in order if record(a.rater,c).exists()],'done_quality':[c for c in order if record(a.rater,c).exists() and read(record(a.rater,c)).get('quality')],'quality_unlocked':unlocked(),'strategies':STRATEGIES,'manifest_state':read(bundle/'manifest.json')['state']})
    if path.startswith('/api/case/'):
     cid=self.cid(path.rsplit('/',1)[1]);p=record(a.rater,cid)
     return self.send({'case':read(bundle/'cases'/(cid+'.json')),'own_annotation':read(p) if p.exists() else None})
    if path.startswith('/api/memory/'):
     if not unlocked():return self.send({'error':'Memory reveal requires BOTH raters to finish ALL blind cases and the coordinator to lock the consensus reference.'},403)
     return self.send(read(bundle/'private'/(self.cid(path.rsplit('/',1)[1])+'.json')))
    if path=='/api/export':return self.send([read(record(a.rater,c)) for c in order if record(a.rater,c).exists()])
    if path.startswith('/images/'):
     name=path.rsplit('/',1)[1];cid=name.rsplit('.',1)[0];self.cid(cid);case=read(bundle/'cases'/(cid+'.json'))
     if name!=case['image']:raise ValueError('Invalid image name')
     return self.send((bundle/'images'/name).read_bytes(),kind='image/png' if name.endswith('.png') else 'image/jpeg')
    return self.send({'error':'Not found'},404)
   except (ValueError,FileNotFoundError) as e:self.send({'error':str(e)},400)
  def do_POST(self):
   try:
    if not self.authorized():return self.send({'error':'Reviewer access token required'},403)
    # Reject browser cross-site writes. Local SSH forwarding remains supported.
    if self.headers.get('Origin') and self.headers['Origin']!='http://'+self.headers.get('Host',''):return self.send({'error':'Cross-origin write rejected'},403)
    length=int(self.headers.get('Content-Length','0'))
    if not 0<length<=2_000_000:raise ValueError('Invalid body length')
    data=json.loads(self.rfile.read(length));cid=self.cid(data['case_id']);p=record(a.rater,cid)
    with mutex:
     if self.path=='/api/blind':
      if p.exists():return self.send({'error':'Blind label is frozen; use adjudication for later corrections.'},409)
      annotation=validate_blind(data['annotation'],read(bundle/'cases'/(cid+'.json')))
      save(p,{'case_id':cid,'rater':a.rater,'blind':annotation,'blind_sha256':digest(annotation),'blind_saved_unix':time.time()})
     elif self.path=='/api/quality':
      if not unlocked():return self.send({'error':'Blind judgments and the consensus reference must be locked first.'},403)
      saved=read(p)
      if saved.get('quality'):return self.send({'error':'Quality review is frozen; discuss corrections separately.'},409)
      saved['quality']=validate_quality(data['annotation']);saved['quality_saved_unix']=time.time();save(p,saved)
     else:return self.send({'error':'Unknown operation'},404)
    self.send({'ok':True})
   except (ValueError,KeyError,FileNotFoundError,json.JSONDecodeError) as e:self.send({'error':str(e)},400)
 port=a.port or (8791 if a.rater=='A' else 8792)
 try:server=ThreadingHTTPServer(('127.0.0.1',port),Handler)
 except OSError:sys.exit(f'Port {port} is already in use. Start again with --port {port+10}.')
 url=f'http://127.0.0.1:{port}/#token={token}'
 print(f'\nReviewer {a.rater} is ready.\nOpen this address in your browser (it is private to this computer):\n\n  {url}\n\nKeep this window open while you work. Press Ctrl+C to stop; your saved labels stay on disk.\nbundle={bundle}',flush=True)
 if a.open:threading.Timer(.6,lambda:webbrowser.open(url)).start()
 try:server.serve_forever()
 except KeyboardInterrupt:print('\nStopped. Saved labels are kept.')
if __name__=='__main__':main()
