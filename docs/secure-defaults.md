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
crypto-random via `secrets.token_urlsafe`), writes it to that file with mode
**0600** and a header that says: *rotate via the admin API after first login,
then delete this file*. The password is never logged — only its path is.
The admin account is created in-process with the same value.

Honest scope note (the trade-off in the open): the repo's standing rule
(`users.py`) is "the service never stores a plaintext credential" — that
design was closed against CodeQL `py/clear-text-storage` for the DEFAULT
path. WP-3.2 asks for generation-into-a-file as a prod feature, so this is
an EXPLICIT, prod-profile-only exception: an env var is readable via
`/proc/<pid>/environ` by any same-user process, a 0600 file is not, and the
operator is instructed to rotate + delete. Default/demo runs never generate
a password and never write a plaintext file (byte-identical to before).

Safety rails:

- generation happens ONLY when the user store is empty (checked at first
  boot). A non-empty store with `FENGARDE_FIRST_BOOT_FILE` set is refused
  with an error — a first-boot file must never silently rotate the live
  admin password;
- the file replaces the env var as the ONLY plaintext holder — an operator
  who sets BOTH should prefer the file and clear the env var;
- `require_auth_or_die` now treats prod as implying auth-is-required, so a
  prod boot can never disagree with `FENGARDE_REQUIRE_AUTH=1` deployments.

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
(aggregation, defaults, short passwords, missing RBAC, redis-bus password),
the first-boot file generation (length, header, POSIX-0600, never-logged),
the demo path being byte-for-byte a no-op, `require_auth_or_die`'s pre-prod
contract, and the non-empty-store rotation refusal via
`ensure_first_boot_admin(password=...)`.

Nothing here touches the `config.js` API-key bootstrap — that is WP-6.1
(GH-2, an auth-model change gated on the owner's decision).