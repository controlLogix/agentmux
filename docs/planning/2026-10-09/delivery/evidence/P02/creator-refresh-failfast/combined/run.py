import os,pathlib,json,subprocess,time,hashlib
root=pathlib.Path(__file__).parent
snapshot=root.parent
src=snapshot/"src/platform"
env=os.environ.copy()
cleared=[]
for name in list(env):
 if name.startswith(("AMX_","AGENTMUX_","DOCKER_")):
  cleared.append(name); del env[name]
env.update({"AMX_BOOTSTRAP_DOCKER_AUTHORIZED":"0","GOPROXY":"off","GOSUMDB":"off","GOWORK":"off","GOTOOLCHAIN":"local","GOENV":"off","GOFLAGS":"-mod=readonly","GORACE":"atexit_sleep_ms=0","GOCACHE":"/home/ryan/.cache/go-build","GOMODCACHE":"/home/ryan/go/pkg/mod"})
argv=["/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go","test","-tags","agentmux_bootstrap_docker","-race","-count=1","-json","./launcher","-run","^(TestBootstrapBoundaryStageTrustedAndClosed|TestBootstrapHistoryBoundaryStageRoundTrip|TestBootstrapBoundaryActualColdMutationGuard|TestBootstrapCleanupFailureRetainsActualSessionAndCauses|TestComposeCLICreatorObservation)$"]
(root/"invocation.json").write_text(json.dumps({"argv":argv,"cwd":str(src),"clearedOverrideNames":sorted(cleared),"fixedEnvironment":{k:env[k] for k in ["AMX_BOOTSTRAP_DOCKER_AUTHORIZED","GOPROXY","GOSUMDB","GOWORK","GOTOOLCHAIN","GOENV","GOFLAGS","GORACE","GOCACHE","GOMODCACHE"]}},indent=2)+"\n")
start=time.monotonic()
with (root/"events.jsonl").open("wb") as stdout,(root/"stderr.log").open("wb") as stderr:
 result=subprocess.run(argv,cwd=src,env=env,stdout=stdout,stderr=stderr)
(root/"exit.json").write_text(json.dumps({"directExit":result.returncode,"executionSeconds":time.monotonic()-start},indent=2)+"\n")
print(json.dumps({"directExit":result.returncode,"executionSeconds":time.monotonic()-start}))
raise SystemExit(result.returncode)
