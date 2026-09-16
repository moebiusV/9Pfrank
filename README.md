# 9Pfrank

A proposed semantic superset of the 9P family. 9Pfrank is the superset dialect; 9P2000, 9P2000.u, and 9P2000.L are supported behind separate frontends, and 9P2000.e compatibility is partial. Original 9P (editions 1–3) is out of scope.

**Status:** proposed design, revision 0.1. A design plan, not an existing standard.

## What it is

9Pfrank preserves 9P's central model: attach to a namespace, obtain fids, walk names, read and write resources, and release references. It treats synthetic files and services as first-class resources. It adds one new dialect with explicit capability negotiation, while keeping legacy dialects behind separate frontends: each frontend maps its dialect's wire format onto 9Pfrank's unified operation set, so supporting the earlier protocols is a bounded, mechanical translation. By default a 9Pfrank server accepts 9P2000, 9P2000.u, and 9P2000.L clients (9P2000.e under review), but only over an authenticated tunnel or a local socket, never in plaintext on an exposed TCP port.

Key properties:

- **Wire format**: a 20-byte native frame header, little-endian fieldwise codecs, typed metadata, and protocol-owned error codes independent of libc.
- **Transport**: TLS 1.3 over TCP as the initial default, with WireGuard as a later option.
- **Operations**: bounded compounds to cut round trips, explicit durability and lock ownership, cancellation with defined outcomes, sparse-file operations and server-side copy.
- **Recovery**: retained-session replay with authenticated resumption.
- **Identity and auth**: authority/subject identity domains, an `AUTH`/`ATTACH` auth-fid flow, and shims for ssh-agent, gpg-agent, Kerberos, OS keyrings, PKCS#11, OIDC/OAuth2, TOTP, and PAM.

## Deliverables

1. **The spec**: the normative protocol specification.
2. **The cookbook**: fun, worked examples on Linux, OpenBSD, and Windows.
3. **The linkable library**: a reusable C99 library with a stable C ABI.
4. **FFI shims**: one `bindings/` subdirectory per language, plus a binding matrix.
5. **The server**: a userspace server.
6. **The client**: a userspace mount client.
7. **The FUSE driver**: a userspace mount backend for the client.
8. **Documentation**: manpages, GNU info, and markdown, in a full GNU autotools layout following GNU standards.

## The plan

The full design and implementation plan (wire layout, operations, compounds, recovery, caching, transport, and delivery phases) lives in [9Pfrank-plan.md](9Pfrank-plan.md).

## License

[ISC](LICENSE).
