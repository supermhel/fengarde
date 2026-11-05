# Secure defaults: `FENGARDE_PROFILE=prod` (WP-3.2)

The zero-config demo (`make demo`, plain `docker compose up`) is untouched:
every check in this profile is gated on `FENGARDE_PROFILE` being exactly
`prod` (case-insensitive). Prod refuses to boot until the WHOLE secure
surface is present — and prints **one aggregated, numbered failure list**, so
an operator fixes everything in one pass instead of one refusal per deploy.

## What prod requires

```
FENGARDE_PROFILE=prod
FENGARDE_API_KEY=<random, ≥ 24 chars>        # ws3 write-surface auth
FENGARDE_RBAC_DB=/path/to/users.sqlite       # role-based access ON (refusal without it)
FENGARDE_ADMIN_PASSWORD=<non-default, ≥ 12>  # OR FENGARDE_FIRST_BOOT_FILE (below)
REDIS_PASSWORD=<set>                          # required when BUS_BACKEND=redis
```

Every failing gate prints, e.g.:

```
FENGARDE_PROFILE=prod but the secure surface is incomplete:
  1) FENGARDE_API_KEY is not set (API-key auth would be OFF)
  2) FENGARDE_RBAC_DB is not set (role-based access would be OFF)
  3) no admin credential: set FENGARDE_ADMIN_PASSWORD or FENGARDE_FIRST_BOOT_FILE ...
```

and exits 1. Known-default credentials (`admin`, `password`, `changeme`,
`fengarde`, `admin123`, ...) are REFUSED — a known admin password with RBAC
on is still default-open.

## First-boot admin password into a FILE (not a log)

In prod, instead of choosing `FENGARDE_ADMIN_PASSWORD`, set:

```
FENGARDE_FIRST_BOOT_FILE=/secrets/admin-password.txt   # inside the container
```

At FIRST boot (empty user store) ws3 generates a strong password (20+ chars,
crypto-random via `secrets.token_urlsafe`), writes it to that file and
creates the admin account in-process with the same value. The password is
never logged - only the file path is. The file is created atomically with
mode **0600** (`O_CREAT|O_EXCL`, mode set at creation, so there is no
world-readable window and a hostile umask cannot widen it), symlinks are
refused, and an existing file is **never overwritten** (a stale or
concurrently created file is an error: delete it and restart). Header text
tells the operator: *rotate via the admin API after first login, then delete
this file*.

Honest scope note (the trade-off in the open): the repo's standing rule
(`users.py`) is "the service never stores a plaintext credential" - that
design was closed against CodeQL `py/clear-text-storage` for the DEFAULT
path. WP-3.2 asks for generation-into-a-file as a prod feature, so this is
an EXPLICIT, prod-profile-only exception. What the file actually buys: the
secret stays OUT of the process environment, so it is not exposed through
`docker inspect`, orchestrator manifests, process listings or shell
history. What it does NOT buy: protection from other processes of the same
uid (they read a 0600 file exactly as they read `/proc/<pid>/environ`), or
from root / volume backups. Recommended: mount the path on a tmpfs or a
secret mount, and delete the file immediately after rotating the password.
Default/demo runs never generate a password and never write a plaintext file
(byte-identical to before).

Windows: the 0600 mode cannot be enforced there (chmod only toggles
read-only; the ACL is inherited from the parent), so generation is
**refused** on Windows and prod startup lists it as a failure - set
`FENGARDE_ADMIN_PASSWORD` instead. Prod targets Linux containers.

Safety rails:

- generation happens ONLY when the user store is empty (checked at first
  boot). A non-empty store with `FENGARDE_FIRST_BOOT_FILE` set logs an error
  and generates nothing - a first-boot file must never silently rotate the
  live admin password;
- two ws3 processes on one RBAC DB cannot both generate: the exclusive file
  create is the lock (the loser creates nothing and logs why), and the file
  is removed again if the admin could not be created, so the password in the
  file is always the admin's. A crash between the file write and the admin
  insert leaves a stale file with an empty store: the next boot refuses
  until the operator deletes it;
- the file replaces the env var as the ONLY plaintext holder - an operator
  who sets BOTH should prefer the file and clear the env var;
- `require_auth_or_die` treats prod as implying auth-is-required, so a
  prod boot can never disagree with `FENGARDE_REQUIRE_AUTH=1` deployments.

## Which entrypoints enforce the gate

| Service | Gate | Why |
|---|---|---|
| ws3-indexer daemon (`main.py`) and triage API `serve()` | full surface (API key, RBAC DB, admin credential, Redis password) | authenticated write/RBAC surface |
| ws6-inventory `serve()` | prod needs at least one provisioned per-tenant key (else it serves open writes) + Redis password | own hashed keystore, no RBAC DB / admin password |
| ws1, ws2, ws4, ws5, ws8, ws9 `main` | Redis-bus password only | bus consumers/producers with a health port, no authenticated API |
| ws1 HTTP ingest | not the prod gate: it already refuses to start without `FENGARDE_INGEST_TOKEN` | own token |
| ws7 dashboard | not wired: nginx image, no Python entrypoint (basic-auth via its own template) | out of scope |

## Example prod compose env (non-demo)

```yaml
services:
  ws3-indexer:
    environment:
      FENGARDE_PROFILE: prod
      FENGARDE_API_KEY: ${FENGARDE_API_KEY:?set it}
      FENGARDE_RBAC_DB: /data/rbac/users.sqlite
      FENGARDE_FIRST_BOOT_FILE: /secrets/admin-password.txt
    volumes:
      - rbac-data:/data/rbac
      - ./secrets:/secrets        # 0600 host dir or k8s secret mount
```

## Tests

`tools/test_prodcheck.py` (fast tier, zero-infra) asserts each refusal
(aggregation, defaults, short passwords, missing RBAC, case-insensitive
redis-bus password), the first-boot file (atomic 0600 under a hostile umask,
no overwrite, symlink refusal, Windows refusal), the ws3 bootstrap
(file password == admin password, never logged, non-empty-store error, race
loser, rollback), every wired entrypoint refusing under prod, the demo path
being byte-for-byte a no-op and `require_auth_or_die`'s pre-prod contract.

Nothing here touches the `config.js` API-key bootstrap — that is WP-6.1
(GH-2, an auth-model change gated on the owner's decision).