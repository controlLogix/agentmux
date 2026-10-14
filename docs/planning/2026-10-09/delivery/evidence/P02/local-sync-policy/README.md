# Local durable sync-policy repair

The local broker factory now sets `sync_interval: always`, as required by STATE-01 S04. Storage limits and protected-account permissions are unchanged.

[Results](results.json) bind the tested source snapshot to 17 focused and 81 affected passing race-test entries, with no failures or skips, plus a clean deployment vet check. The prepared NATS 2.15 broker accepted the configuration. An authenticated fixture-administrator VARZ query observed `sync_always=true`; missing and periodic settings produced false in separate owned fixture restarts. Private configuration and complete responses were not copied into evidence.

This is WSL evidence, not native macOS/Linux, Compose or power-loss qualification. The coordinator owns the final source registration, caller refusal checks, candidate commit/push and phase review. Historical evidence is retained; the earlier missing-setting record is not relabeled as passing.
