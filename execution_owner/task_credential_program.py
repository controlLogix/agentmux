"""Fixed in-container NKey proof; never returns seed or credential bytes."""
# The selected pinned ARM64 Python image supplies OpenSSL. No caller chooses an
# executable, file, key, arbitrary signing purpose or signing destination.
PROOF = r'''
import base64,binascii,json,os,re,subprocess,sys,time
from datetime import datetime,timezone
try:
    fd=os.open('/run/agentmux/credential',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        import stat
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or not 0<info.st_size<=16384:raise ValueError()
        raw=os.read(fd,16385)
    finally:os.close(fd)
    value=json.loads(raw)
    if set(value)!={'format','record','credentialsBase64'} or value['format']!='agentmux-task-credential-private-v1':raise ValueError()
    record=value['record'];request=json.loads(sys.stdin.buffer.read(16385))
    if time.time()>=record['expiresUnix'] or request['generationRef']!=record['generationRef'] or request['runRef']!=record['runRef']:raise ValueError()
    material=base64.b64decode(value['credentialsBase64'],validate=True)
    seeds=re.findall(rb'(?m)^SU[A-Z2-7]+$',material)
    if len(seeds)!=1:raise ValueError()
    encoded=seeds[0];decoded=base64.b32decode(encoded+b'='*(-len(encoded)%8))
    if len(decoded)!=36:raise ValueError()
    # The host validates NKey CRC/public-key/JWT bindings before delivery. The
    # in-container signer consumes only its already bound 32-byte private seed.
    seed=decoded[2:34]
    if request['purpose']=='broker-nonce':
        if set(request)!={'purpose','generationRef','runRef','nonce'} or not re.fullmatch(r'[A-Za-z0-9_-]{15,512}',request['nonce']):raise ValueError()
        message=request['nonce'].encode('ascii')
    elif request['purpose']=='task-inspect':
        if set(request)!={'purpose','generationRef','runRef','claims'}:raise ValueError()
        claims=request['claims']
        if (claims['purpose']!='agentmux-client-possession-v1' or claims['contractId']!='task-inspect'
            or claims['payload']!={'taskId':record['taskRef']['id']} or claims['profileId']!=record['profileId']
            or claims['hubId']!=record['runRef']['ownerHubId'] or claims['authorityId']!=record['authorityId']
            or claims['transportRef']!=record['transportRef'] or claims['grantRef']!=record['taskReadGrantRef']
            or claims['expectedVersion']!=record['taskRef']['revision'] or claims['approvalRefs']!=record['taskApprovalRefs']
            or claims['replySubject']!=record['replySubject'] or claims['operationId']!=record['readOperationId']
            or set(claims)!={'purpose','profileId','hubId','authorityId','transportRef','grantRef','operationId',
                'expectedVersion','contractId','payload','approvalRefs','issuedAt','expiresAt','replySubject'}):raise ValueError()
        start=datetime.fromisoformat(claims['issuedAt']);end=datetime.fromisoformat(claims['expiresAt'])
        if (start.tzinfo is None or end.tzinfo is None or start.utcoffset()!=timezone.utc.utcoffset(start)
            or end.utcoffset()!=timezone.utc.utcoffset(end) or not record['issuedUnix']<=start.timestamp()<=time.time()+1
            or not time.time()<end.timestamp()<=record['expiresUnix'] or start>=end):raise ValueError()
        # This closed claims shape is ASCII and integral; canonical JSON agrees
        # with JCS for the fixed identifier/reference fields used here.
        message=json.dumps(claims,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    else:raise ValueError()
    keyfd=os.memfd_create('task-key',os.MFD_CLOEXEC);datafd=os.memfd_create('task-proof',os.MFD_CLOEXEC)
    try:
        os.write(keyfd,bytes.fromhex('302e020100300506032b657004220420')+seed)
        os.write(datafd,message);os.lseek(keyfd,0,0);os.lseek(datafd,0,0)
        result=subprocess.run(['/usr/bin/openssl','pkeyutl','-sign','-rawin','-keyform','DER',
            '-inkey','/proc/self/fd/'+str(keyfd),'-in','/proc/self/fd/'+str(datafd)],
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,pass_fds=(keyfd,datafd),timeout=2)
        if result.returncode or len(result.stdout)!=64:raise ValueError()
        sys.stdout.buffer.write(base64.b64encode(result.stdout))
    finally:os.close(keyfd);os.close(datafd)
except BaseException:
    sys.exit(1)
'''
