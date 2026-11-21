"""Prepare exact, authorized email attachments at readiness; never claims to send mail."""
import argparse,fcntl,hashlib,html,json,sys,time,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'research/human_review_memjack'))
from common import read,save,file_sha,verify_bundle
LIMIT=18*1024*1024

def split_zip(source,out,limit=LIMIT,prefix='memjack-review'):
    """Each part is a regular ZIP; extract ALL parts into the same directory."""
    out.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(source) as src:
        if src.testzip() is not None:raise ValueError('Source ZIP failed CRC')
        groups=[];group=[];size=0
        for item in src.infolist():
            if item.is_dir():continue
            if item.file_size>limit-65536:raise ValueError('One file is too large for an email part')
            if group and size+item.file_size>limit-65536:groups.append(group);group=[];size=0
            group.append(item);size+=item.file_size
        if group:groups.append(group)
        paths=[]
        for i,items in enumerate(groups,1):
            path=out/f'{prefix}-part-{i:03d}-of-{len(groups):03d}.zip'
            with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as dest:
                for item in items:dest.writestr(item.filename,src.read(item))
                dest.writestr('EXTRACT_ALL_PARTS.txt',f'This is part {i} of {len(groups)}. Extract EVERY part into the SAME folder, keeping toolkit/ and bundle/ directories. Then open START_HERE.txt. Do not begin labeling until all parts are extracted.\n')
            if path.stat().st_size>limit:raise ValueError('Email part exceeds attachment budget')
            with zipfile.ZipFile(path) as check:
                if check.testzip() is not None:raise ValueError('Part CRC failure')
            paths.append(path)
    return paths

def prepare(request,out):
    spec=read(request);bundle=Path(spec['source_bundle']);archive=Path(spec['source_archive'])
    if not (bundle/'manifest.json').exists() or not archive.exists():return {'state':'waiting_for_frozen_bundle','recipient':spec['recipient'],'automatic_email_scheduled':False}
    m=verify_bundle(bundle)
    if m['state']!='FROZEN' or m['population']!=spec['required_population'] or m['primary_n']!=spec['primary_sample_size']:raise ValueError('Wrong cohort/settings; never mail a demo or incomplete batch')
    cfg=read(bundle/'protocol.json')
    if cfg['reviewers']!=spec['reviewers']:raise ValueError('Reviewer setting mismatch')
    if not (archive.with_suffix(archive.suffix+'.sha256')).exists() or file_sha(archive)!=archive.with_suffix(archive.suffix+'.sha256').read_text().split()[0]:raise ValueError('Archive checksum mismatch')
    out.mkdir(parents=True,exist_ok=True)
    paths=split_zip(archive,out/'attachments',prefix=f"memjack-review-{m['population']}") if archive.stat().st_size>LIMIT else [archive]
    frame=read(bundle/'private/frame.json');pl=sorted({x.get('judge_protocol','unknown') for x in frame});counts={k[-2:]:sum(x.get('judge_protocol')==k for x in frame) for k in pl};mix=' + '.join(f'{v} {k}' for k,v in counts.items())
    messages=[]
    for i,path in enumerate(paths,1):
        content=f'''<p>Hello,</p><p>The MemJack human-review package is ready: <strong>{m['population']} unique, structurally valid full-episode records</strong> from two judge-pipeline versions ({mix}; each version used one fixed prompt, and the mixture is tracked per record). Retries and unresolved records are excluded.</p><p>Reviewers A and B independently review the SAME {m['primary_n']} randomly sampled episodes, plus {m['supplement_n']} success-stratum supplements ({m['assigned_per_reviewer']} episodes per reviewer). First complete blinded source review, then resolve disagreements and freeze the reference, and only then reveal the LLM memory proposals.</p><p>The attached package includes actual images, complete saved prompts/responses for assigned cases, the local review UI, English guidelines, the prespecified statistical plan and tests. It contains no prefilled human labels. Passing the sample audit does not certify every unreviewed label or demonstrate defense effectiveness.</p><p>This email carries attachment {i} of {len(paths)}. Download and extract ALL ZIP parts into the SAME directory before starting. Then open <code>START_HERE.txt</code>: the review page starts with one double-click (<code>toolkit/start_review.bat</code> on Windows, <code>toolkit/start_review.command</code> on macOS, or <code>python3 toolkit/start_review.py</code>) and opens in your browser; it asks whether you are reviewer A or B. Please read <code>toolkit/GUIDELINES_EN.md</code> first (it is also under the Guidelines button). Python 3.10+ is the only requirement; no GPU is needed.</p><p>Attachment: {html.escape(path.name)}<br>SHA-256: <code>{file_sha(path)}</code><br>Full archive SHA-256: <code>{file_sha(archive)}</code></p><p>This is a research candidate-label audit, not human gold or a claim of successful real-world attack execution.</p>'''
        message={'part':i,'to':spec['recipient'],'subject':f"MemJack: {m['population']}-case two-reviewer audit package [{i}/{len(paths)}]",'payload':{'mime_type':'text/html','body':{'content':content}},'attachment_paths':[str(path.resolve())],'attachment_bytes':path.stat().st_size,'attachment_sha256':file_sha(path),'send_state':'awaiting_connected_gmail_dispatch'}
        save(out/f'message-{i:03d}.json',message);messages.append(message)
    result={'state':'ready_for_connected_gmail_dispatch','recipient':spec['recipient'],'population':m['population'],'primary_n':m['primary_n'],'assigned_per_reviewer':m['assigned_per_reviewer'],'archive':str(archive),'archive_sha256':file_sha(archive),'messages':messages,'automatic_email_scheduled':False,'sent':False,'reason':'Connected Gmail tools can send now in an active assistant turn, but no unattended conditional-send service is available. User authorization is saved; do not request it again.','prepared_unix':time.time()}
    save(out/'outbox.json',result);return result

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--request',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);ap.add_argument('--watch',action='store_true');a=ap.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    lock=(a.out/'preparer.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    while True:
        if (a.out/'outbox.json').exists():print('Existing prepared outbox preserved; no email sent.',flush=True);break
        result=prepare(a.request,a.out);save(a.out/'status.json',dict(result,updated_unix=time.time()));print(json.dumps({k:v for k,v in result.items() if k!='messages'}),flush=True)
        if result['state']!='waiting_for_frozen_bundle' or not a.watch:break
        time.sleep(60)
