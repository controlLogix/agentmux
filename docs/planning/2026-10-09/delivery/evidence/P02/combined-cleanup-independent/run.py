from pathlib import Path
import os,json,subprocess
out=Path(__file__).resolve().parent;fixed={"GOTOOLCHAIN":"local","GOPROXY":"off","GOSUMDB":"off","GOWORK":"off","GORACE":"atexit_sleep_ms=0","AGENTMUX_TEST_NATS":"/home/ryan/.cache/agentmux-governance/tools/nats-server"};env=os.environ.copy();env.update(fixed);go="/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go";commands={"focused":[go,"test","-race","-count=1","-json","./launcher","-run","^(TestOwnerBridgeTerminalFailureReleasesServiceLease|TestRuntimeCleanup|TestSessionCloseHonorsHeldLockDeadline|TestTransportCleanup)"],"vet":[go,"vet","./launcher"]}
(out/"invocation.json").write_text(json.dumps({"cwd":str(out/"platform"),"commands":commands,"fixedEnvironment":fixed},indent=2)+"\n");exits={}
for name,args in commands.items():
 with (out/(name+".stdout")).open("wb")as stdout,(out/(name+".stderr")).open("wb")as stderr:result=subprocess.run(args,cwd=out/"platform",env=env,stdout=stdout,stderr=stderr)
 exits[name]=result.returncode;(out/"exits.json").write_text(json.dumps(exits)+"\n")
raise SystemExit(any(exits.values()))
