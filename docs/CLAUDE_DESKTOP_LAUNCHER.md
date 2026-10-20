# Claude Desktop startup launcher

The launcher source is `hub/client_launch_desktop.py`. Native dispatcher,
protected admission, bootstrap and package roster are implemented in source.
The installed candidate has not been rebuilt with this route. Offline tests
pass; installed execution and actual Claude Desktop launch remain unqualified.

The intended installed entry point is:

```sh
"/Library/Application Support/Agentmux/Protected/agentmux-runtime" \
  launch-claude-desktop --client-installation INSTALLATION_ID \
  --selection "/absolute/private/client-selection.json"
```

The native entry point must admit the protected client installation before
entering `hub.client_launch_desktop.main(["--selection", selection])`. It must
retain the existing isolated Python bootstrap and private selection checks.
The installation ID and selection are explicit; the current directory and
environment cannot choose them.

The launcher checks the fixed `/Applications/Claude.app` bundle and its
`com.anthropic.claudefordesktop` identifier. It then runs ordinary enrolled
startup once, writes the safe status summary to stderr, and finishes cleanup
on the original startup handles. Confirmed infrastructure readiness may be
`ready` or `degraded`; setup, progress, failure and unknown readiness do not
open the app. Requested application binding failure also prevents launch.

After cleanup, it checks the fixed app again and replaces its own process with
`/usr/bin/open -a /Applications/Claude.app`. It accepts no executable path,
alternate client, application arguments, worker flag or output-mode override.
Process replacement leaves no additional launcher child to abandon. The
shared runtime remains under its existing host owner, and app closure does not
stop it.

This identifies an existing user-installed client; it does not attest the
client's signature, change its settings, copy its credentials, or grant business
command access. Claude Desktop retains its native authentication and existing
MCP configuration. The launcher itself requires no HOST business credentials.
An app installed elsewhere needs an explicitly supported route; this launcher
does not search for a substitute.

If the app is absent or startup cannot be confirmed, the launcher exits with a
fixed diagnostic. Use the enrolled startup and prerequisite diagnostics to
correct the installation or selection, then invoke the same launcher again.
SIGTERM, SIGHUP and SIGINT fence app opening. Their handlers record termination
without raising during process allocation or cleanup. The current bounded startup
response hands back its original handles, and cleanup joins those handles before
the launcher exits. Repeated termination requests do not replace or cancel that
cleanup. The first signal determines the exit status, and prior handlers are
restored when control returns. Final cleanup can exceed the startup response
budget if the original child cannot yet be reaped. SIGKILL cannot be handled;
this launcher does not claim cleanup after SIGKILL or operating-system failure.
Disabling this launcher preserves alternate CLI access, client settings and
durable data.

Native qualification still needs the admitted installed entry point, the
intended user's enrollment, a root-coordinated live slot, actual app startup and
reuse, visible status, concurrent launches, and closure while another session
has durable work. Lazy MCP initialization alone does not qualify this launcher.
