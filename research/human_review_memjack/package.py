"""Portable internal handoff ZIP: toolkit + frozen review assets, no credentials."""
import argparse,hashlib,json,zipfile
from pathlib import Path
HERE=Path(__file__).resolve().parent

def package(bundle,target):
 if target.exists():raise ValueError('Refuse to overwrite an existing archive')
 target.parent.mkdir(parents=True,exist_ok=True)
 with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
  for p in sorted(HERE.rglob('*')):
   if not p.is_file() or '__pycache__' in p.parts or p.suffix=='.pyc':continue
   z.write(p,Path('toolkit')/p.relative_to(HERE))
  for p in sorted(bundle.rglob('*')):
   if not p.is_file() or p.name in ['access-token.txt','server.lock'] or p.suffix=='.lock':continue
   # New handoffs contain no prefilled human labels or browser/session secrets.
   if 'annotations' in p.relative_to(bundle).parts:continue
   z.write(p,Path('bundle')/p.relative_to(bundle))
  z.writestr('START_HERE.txt','MEMJACK HUMAN REVIEW - QUICK START\n\n1. Extract ALL zip parts into ONE folder. It must contain "toolkit" and "bundle".\n2. Install Python 3.10+ if needed (https://www.python.org/downloads/). Nothing else is required.\n3. Start the review page:\n   Windows : double-click toolkit\\start_review.bat\n   macOS   : double-click toolkit/start_review.command (first time: right-click > Open)\n   Linux   : bash toolkit/start_review.sh\n   Any OS  : python3 toolkit/start_review.py A     (or B)\n4. Your browser opens the review page. Keep the black window open while you work.\n5. Your progress is saved on this computer. You can stop and continue later with the same step 3.\n\nReviewers A and B review the SAME cases independently and must not discuss them until both finish.\nBefore you start read toolkit/GUIDELINES_EN.md (also under the Guidelines button in the page).\nThe bundle manifest identifies DEMO vs frozen 700-case data. No human labels are prefilled.\n')
 with zipfile.ZipFile(target) as z:
  if z.testzip() is not None:raise ValueError('ZIP integrity failure')
 sha=hashlib.sha256(target.read_bytes()).hexdigest();target.with_suffix(target.suffix+'.sha256').write_text(sha+'  '+target.name+'\n')
 return {'zip':str(target),'bytes':target.stat().st_size,'sha256':sha}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--bundle',type=Path,required=True);p.add_argument('--zip',type=Path,required=True);a=p.parse_args();print(json.dumps(package(a.bundle,a.zip)))
