# Initial runtime command matrix run

The command tests and matrix validation returned zero, but the runner returned one during its final evidence step. That step checked paths relative to the package directory instead of the snapshot root. Its original failed source check is retained; it does not prove source drift. The runner now selects the snapshot root before checking source hashes. This record is historical, not a passing collector run.
