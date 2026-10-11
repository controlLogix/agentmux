$taskRoot = Split-Path -Parent $PSCommandPath
$taskNeedle = 'agentmux original calibration MCP retry d25f60ab89ac46afb6d60a5284ccdebb'
$taskMatches = @(Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -and $_.CommandLine.Contains($taskNeedle) -and $_.Name -in @('python.exe','python3.exe','node.exe','codex.exe','powershell.exe','pwsh.exe','cmd.exe') } | Select-Object ProcessId,ParentProcessId,Name,CreationDate,CommandLine)
$taskResult = @{ scope='Current process observation only; no exact job accounting is available';knownNodePid=21732;knownNodePidPresent=[bool](Get-Process -Id 21732 -ErrorAction SilentlyContinue);fixtureProcessesExceptProbe=$taskMatches }
$taskResult | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $taskRoot 'windows-terminal-observation-final.json') -Encoding utf8
$taskResult | ConvertTo-Json -Depth 5
