set -eu
umask 077
root=/home/ryan/.cache/agentmux-governance
out=$(mktemp -d "$root/p02-midboot-repaired-compile-XXXXXX")
printf '%s\n' "$out"
cp /mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-midboot-repaired-compile.sh "$out/producer.sh"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0 AMX_BOOTSTRAP_DOCKER_AUTHORIZED=0
GO="$root/runtime-comparison/go/bin/go"
python3 - "$out" "$GO" <<'PY'
import pathlib,hashlib,json,shutil,os,sys,datetime
p=pathlib.Path(sys.argv[1]);live=pathlib.Path('/mnt/c/Users/RyanHelms/GitHub/agentmux');draft=pathlib.Path('/home/ryan/.cache/agentmux-governance/p02-installed-cli-midboot-draft-erisu2sf/installed_cli_midboot_compose_integration_linux_test.go')
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def scan(root):return {str(f.relative_to(root)):sha(f) for sub in ['platform','contracts'] for f in sorted((root/sub).rglob('*')) if f.is_file()}
before=scan(live)
for sub in ['platform','contracts']:shutil.copytree(live/sub,p/'src'/sub)
after=scan(live);assert before==after==scan(p/'src');assert sha(draft)=='c555fb92e6d6cf08c00d3b640628be71811e8c80fc61da2a926e30c768776e0f';target=p/'src/platform/launcher'/draft.name;assert not target.exists();shutil.copyfile(draft,target)
for name,m in [('shared-before',before),('shared-after',after),('source-manifest',scan(p/'src'))]:(p/(name+'.json')).write_text(json.dumps(m,indent=2)+'\n')
(p/'invocation.json').write_text(json.dumps({'argv':[sys.argv[2],'test','-count=1','-json','-tags=agentmux_bootstrap_docker','./launcher','-run','^$'],'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'environment':{k:os.environ[k] for k in ['GOPROXY','GOSUMDB','GOWORK','GORACE','AMX_BOOTSTRAP_DOCKER_AUTHORIZED']},'batchSourceVerification':True,'companionSHA256':sha(target),'producerSHA256':sha(p/'producer.sh'),'engineCalls':0,'purpose':'Compile the tagged cache-only fixture; execute no tests'},indent=2)+'\n')
PY
cd "$out/src/platform"
set +e
"$GO" test -count=1 -json -tags=agentmux_bootstrap_docker ./launcher -run '^$' > "$out/events.jsonl" 2> "$out/stderr.log"
code=$?
printf '%s\n' "$code" > "$out/exit.txt"
exit "$code"