# Configuration Source of Truth

## Runtime hierarchy

`Control Center -> ControlCenter state -> security/policy gates -> feature runtime`

`backend/app/control_center.py` owns the validated mutable runtime policy. Its
document is versioned, atomically written, backed up and reloaded on startup.
Unknown fields and invalid cross-field combinations are rejected.

## Environment configuration

The project-root `.env` remains for installation and immutable startup
parameters: environment, authentication token, loopback/auth policy, database
and workspace paths, shell path, backend choice, fixed safety ceilings,
provider endpoint and operator options.

Legacy feature variables remain compatibility ceilings. A feature is allowed
only when both its startup ceiling and Control Center gate permit it. `.env`
must never turn a denied runtime operation on. New mutable toggles belong only
in the typed Control Center model.

## Persistence

Mutable state is stored in `control_center.json` beside the database. Writes
use temporary file + `fsync` + `os.replace`; the previous valid file is kept
as `.bak`. Persistence failure rolls back memory state and is audited.

Emergency Stop persists across backend restarts. Only explicit Resume clears
it. Host Control does not automatically activate an executor after restart.

## Feature versus authorization

- Terminal enabled does not authorize Host Control or sudo.
- Host Control requires a user-confirmed switch and mode change.
- Network enabled remains constrained by destination policy.
- Tools remain constrained by per-tool permission and approval.
- Emergency Stop overrides all high-impact feature settings.

## Migration rule

Do not add another configuration database. Retire a legacy environment feature
flag only through an explicit migration with backward-compatibility tests.