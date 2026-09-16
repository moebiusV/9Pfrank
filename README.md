# 9Pfrank

A proposed semantic superset of the 9P family — all dialects are supported: 9P2000, 9P2000.u, 9P2000.L, and 9P2000.e — and 9Pfrank is the superset dialect.

**Status:** proposed design, revision 0.1. A design plan, not an existing standard.

## What it is

9Pfrank preserves 9P's central model — attach to a namespace, obtain fids, walk names, read and write resources, and release references — and treats synthetic files and services as first-class resources. It adds one new dialect with explicit capability negotiation, while keeping legacy dialects behind separate frontends: each frontend maps its dialect's wire format onto 9Pfrank's unified operation set, so supporting the earlier protocols is trivial. By default, a 9Pfrank server accepts connections from 9P2000, 9P2000.u, 9P2000.L, 9P2000.e, and original 9P clients.

Key properties:

- **Wire format** — a 32-byte native frame, little-endian fieldwise codecs, typed metadata, and protocol-owned error codes independent of libc.
- **Transport** — TLS 1.3 over TCP as the initial default, with WireGuard as a later option.
- **Operations** — bounded compounds to cut round trips, explicit durability and lock ownership, cancellation with defined outcomes, sparse-file operations and server-side copy.
- **Recovery** — retained-session replay with authenticated resumption.
- **Identity and auth** — authority/subject identity domains, an `AUTH`/`ATTACH` auth-fid flow, and shims for ssh-agent, gpg-agent, Kerberos, OS keyrings, PKCS#11, OIDC/OAuth2, TOTP, and PAM.

## The plan

The full design and implementation plan — wire layout, operations, compounds, recovery, caching, transport, and delivery phases — lives in [9Pfrank-plan.md](9Pfrank-plan.md).

## License

[ISC](LICENSE).
