"""One-step launcher for human reviewers: finds the bundle, asks A/B, starts the local review page and opens the browser."""
import argparse,socket,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent

def find_bundle(given):
 if given:return Path(given).expanduser().resolve()
 for c in [HERE.parent/'bundle',HERE/'bundle',Path.cwd()/'bundle']:
  if (c/'manifest.json').exists():return c.resolve()
 sys.exit('Could not find the review bundle. Extract ALL ZIP parts into one folder so that it contains both "toolkit" and "bundle", then start again.\nOr run: python start_review.py A --bundle /path/to/bundle')

def free_port(start):
 for port in range(start,start+20):
  with socket.socket() as s:
   if s.connect_ex(('127.0.0.1',port))!=0:return port
 sys.exit('No free local port found between %d and %d.'%(start,start+19))

def main():
 if sys.version_info<(3,10):sys.exit('Python 3.10 or newer is required (you have %d.%d). Download it from https://www.python.org/downloads/'%sys.version_info[:2])
 ap=argparse.ArgumentParser(description='Start the MemJack review page.');ap.add_argument('rater',nargs='?',choices=['A','B','a','b']);ap.add_argument('--bundle');ap.add_argument('--port',type=int);ap.add_argument('--no-open',action='store_true',help='do not open the browser automatically');a=ap.parse_args()
 rater=(a.rater or '').upper()
 while rater not in ('A','B'):
  rater=input('Which reviewer are you? Type A or B and press Enter: ').strip().upper()
 bundle=find_bundle(a.bundle);port=a.port or free_port(8791 if rater=='A' else 8792)
 print(f'Using bundle: {bundle}')
 sys.path.insert(0,str(HERE))
 import serve
 sys.argv=['serve.py','--bundle',str(bundle),'--rater',rater,'--port',str(port)]+([] if a.no_open else ['--open'])
 serve.main()
if __name__=='__main__':main()
