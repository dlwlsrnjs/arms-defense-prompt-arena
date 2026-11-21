#!/usr/bin/env python3
"""Recover COCO images by dataset/split/ID; do not claim author-copy byte identity."""
import concurrent.futures
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import time
import urllib.request
import zipfile
from PIL import Image
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'research/runtime/memjack-audit-20261119'
BASE=OUT/'image-sources/coco2017'
def file_sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def info(path):
 with Image.open(path) as image:
  image.load();h=hashlib.sha256();h.update(image.mode.encode());h.update(repr(image.size).encode());h.update(image.tobytes())
  return {'width':image.width,'height':image.height,'mode':image.mode,'pixel_sha256':h.hexdigest(),'file_sha256':file_sha(path)}
def main():
 items=json.loads((OUT/'image-inventory.json').read_text());result=[]
 selected=[v for v in items if re.fullmatch(r'COCO_(?:val|train)2017:\d{12}',v['canonical_image'])]
 archive=BASE/'val2017.zip'
 with zipfile.ZipFile(archive) as z:
  bad=z.testzip()
  if bad:raise ValueError('CRC mismatch: '+bad)
  for v in selected:
   corpus,image_id=v['canonical_image'].split(':');split=corpus.removeprefix('COCO_')
   if split!='val2017':continue
   name=split+'/'+image_id+'.jpg';p=BASE/name
   try:
    p.parent.mkdir(parents=True,exist_ok=True)
    if not p.exists():
     with z.open(name) as src,p.open('wb') as dest:shutil.copyfileobj(src,dest)
    result.append({'canonical_image':v['canonical_image'],'status':'resolved','path':str(p),'source':'pcuenq/coco-2017-mirror@fbbee70f52f540987cca6936c9f1d7b1ff969ad1/val2017.zip','original_author_pixel_identity_attested':False,**info(p)})
   except Exception as e:result.append({'canonical_image':v['canonical_image'],'status':'error','error':str(e)})
 def download(v):
  corpus,image_id=v['canonical_image'].split(':');p=BASE/'train2017'/f'{image_id}.jpg';p.parent.mkdir(parents=True,exist_ok=True)
  url=f'https://s3.amazonaws.com/images.cocodataset.org/train2017/{image_id}.jpg'
  try:
   if not p.exists():
    error=None
    for attempt in range(3):
     try:
      with urllib.request.urlopen(url,timeout=30) as f:raw=f.read(20000000)
      with Image.open(io.BytesIO(raw)) as im:im.load()
      tmp=p.with_suffix('.tmp');tmp.write_bytes(raw);tmp.replace(p);error=None;break
     except Exception as e:error=e;time.sleep(attempt+1)
    if error:raise error
   return {'canonical_image':v['canonical_image'],'status':'resolved','path':str(p),'source':url,'original_author_pixel_identity_attested':False,**info(p)}
  except Exception as e:return {'canonical_image':v['canonical_image'],'status':'error','error':str(e)}
 with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:result.extend(pool.map(download,[v for v in selected if v['source_corpus']=='COCO_train2017']))
 known={v['canonical_image'] for v in result}
 for v in items:
  if v['canonical_image'] not in known:result.append({'canonical_image':v['canonical_image'],'status':'unresolved','reason':'No unambiguous source dataset image ID resolver configured; never match on basename alone.'})
 (OUT/'resolved-images.json').write_text(json.dumps(result,indent=2)+'\n')
 counts={status:sum(v['status']==status for v in result) for status in ['resolved','error','unresolved']}
 summary={'canonical_image_counts':counts,'resolved_trajectories':sum(len(v['trajectory_ids']) for v in items if any(r['canonical_image']==v['canonical_image'] and r['status']=='resolved' for r in result)),'source_archive_sha256':file_sha(archive),'author_copy_hashes_available':False,'verification_level':'Source dataset/split/ID recovered and decoded. No published author image hashes to establish exact copy identity.'}
 (OUT/'image-resolution-summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
