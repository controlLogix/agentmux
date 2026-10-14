from pathlib import Path
import os,json,subprocess
out=Path(__file__).resolve().parent;go="/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go";fixed={"GOTOOLCHAIN":"local","GOPROXY":"off","GOSUMDB":"off","GOWORK":"off","GORACE":"atexit_sleep_ms=0"};env=os.environ.copy();env.update(fixed);args=[go,"test","-race","-count=1","-json","./launcher","-run","^(TestFixedTLSArchiveReadsActuallyOverlap|TestFixedTLSArchiveFailureCancelsAndJoinsActualChildren|TestFixedTLSArchiveDeadlineJoinsActualChildren|TestFixedTLSArchiveOwnershipFailureStartsNoArchive)$"]
(out/"invocation.json").write_text(json.dumps({"cwd":str(out/"platform"),"argv":args,"fixedEnvironment":fixed},indent=2)+"\n")
with (out/"focused.jsonl").open("wb")as stdout,(out/"focused.stderr").open("wb")as stderr:result=subprocess.run(args,cwd=out/"platform",env=env,stdout=stdout,stderr=stderr)
(out/"exit.json").write_text(json.dumps({"returncode":result.returncode})+"\n");raise SystemExit(result.returncode)
