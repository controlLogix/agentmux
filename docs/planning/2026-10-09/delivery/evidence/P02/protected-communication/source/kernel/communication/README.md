# Initial protected broker boundary

`BuildConfig(hubID, port, credentials)` returns private JSON configuration bytes for a loopback Core NATS broker. `BuildConfigWithListener` also accepts an explicit `Listener` with `NativeLoopback` or `ContainerInternal` mode. Container mode binds `0.0.0.0` inside the container; deployment must separately publish only on the private host loopback interface. No ambient state chooses this mode. `Subjects(hubID)` returns the exact fixed subjects. Hub IDs use the same opaque token syntax as the protected assembly; dots, wildcards and path syntax are rejected. Config bytes contain secrets and must remain in a private deployment store. The builder does not write files, log secrets or read existing user credentials.

The separate new wire namespace is `amx.v1.h.<hub>.kernel`. It does not reuse legacy `am.*` traffic or register an implicit SDK business route.

| Account and user | Publication | Subscription |
| --- | --- | --- |
| SYS / deployment-admin | `$SYS.>` and `_INBOX.>` for broker administration | The same system and reply subjects |
| KERNEL / boot and kernel-lifecycle | Own event and the four exact member command subjects | Own command and four exact protected event subjects |
| KERNEL / internal-communication | Own event | Own command and four exact protected event subjects |
| KERNEL / exported-status | Own event plus exact snapshot and update | Own command and four exact protected event subjects |
| APPLICATION / ordinary-plugin | None | Exact imported snapshot and update only |

Protected role names are `boot`, `kernel-lifecycle`, `internal-communication` and `exported-status`. Internal subjects are `amx.v1.h.<hub>.kernel.internal.<role>.command` and `.event`. The only exports are `amx.v1.h.<hub>.kernel.status.snapshot` and `.update`, exported to APPLICATION as streams. No system exports, service imports or implicit default-account users are configured. Every identity has a distinct caller-supplied secret containing 32–256 ASCII letters, digits, `_` or `-`. The deployment owner must generate those secrets securely; syntax validation does not measure entropy. Protected clients cannot access `$SYS` or `$JS` management subjects. Ordinary clients cannot publish, use request inboxes, subscribe to internal traffic or widen the exact status subscription with wildcards.

Broker identity does not prove release integrity or authorize application actions. The deployment owner must bind each private credential to its verified protected member. The exported-status producer still needs to implement accepted L04 observations, actual readiness and permitted caller scope, including signatures where required. This account fixture does not qualify that producer.

The tests use independent, disposable NATS 2.15 processes and randomized private local secrets. Set `AGENTMUX_TEST_NATS` to the prepared server executable and run `go test ./kernel/communication` from `platform`. Tests verify permitted cross-account stream delivery, role commands/events and real broker rejections for forgery, wildcard subscriptions, request traffic and system/JetStream management. Configurations and broker logs stay in private disposable directories and are never printed or copied into review evidence.

This is initial trusted local bootstrap isolation. JWT enrollment, rotation/revocation, per-plugin capability construction, confidential project accounts, domain authorization, business persistence and partner exports remain with P03/P04/P10 owners. File-backed JetStream and capacity configuration remain P02-T05 responsibilities. The fixture uses Core NATS and makes no production authentication, persistence, federation or sandboxing claim. Account configuration is infrastructure before boot; post-boot plugin traffic uses NATS.
