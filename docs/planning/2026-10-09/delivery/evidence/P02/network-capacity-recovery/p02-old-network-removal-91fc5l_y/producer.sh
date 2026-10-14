cd /home/ryan/.cache/agentmux-governance/p02-old-network-removal-91fc5l_y/platform
/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go fmt ./launcher >/dev/null
RECOVERY_OUTPUT=/home/ryan/.cache/agentmux-governance/p02-old-network-removal-91fc5l_y GOPROXY=off GOSUMDB=off /home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go test ./launcher -run "^TestRecoveryNetworkPreparation$" -count=1 -v -timeout=240s > ../events.log 2> ../stderr.log
result=$?
echo "$result" > ../exit.txt
cat ../events.log
cat ../stderr.log
