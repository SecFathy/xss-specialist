# Rollback

The registry (`registry/registry.py`) keeps every adapter version with full lineage. Rollback
restores a prior version's `current` pointer **without retraining**.

## Model
```python
from registry.registry import Registry
r = Registry()
r.promote("v002", "canary")   # sets rollback_target = previous current
# ... regression detected in v003 after it was promoted ...
r.rollback()                  # current -> the prior good version; no retraining
```
`rollback()` swaps `current` and `rollback_target`, so a rollback is itself reversible. The adapter
files are immutable, so restoring a pointer restores exact behaviour (reproducible from
`adapter_sha256`).

## Simulated V1→V2→V3 regression test
`registry` records each version's eval; introduce a regression in V3, verify the gate would REJECT
it (or, if promoted then found regressed in canary, `rollback()` restores V2). Registry consistency
is checked by re-reading each version's `adapter_sha256`.

## Data / benchmark
Every result records the split's `sha256`. If a benchmark bug is found, the integrity rule applies:
document it, preserve the old result, fix, rerun only what is scientifically justified, explain the
change — never overwrite history.
