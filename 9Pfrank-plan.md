# 9Pfrank: protocol design and implementation plan

Status: proposed design, revision 0.1, 2026-09-14. This is a design plan, not an existing standard or a claim of client support. All layouts, numbers, limits, and requirements below are proposed. `MUST` and `SHOULD` describe the intended contract. Freeze the wire format only after two independent implementations interoperate.

## 1. Direction

Build a semantic superset of 9P2000, 9P2000.u, 9P2000.L, 9P2000.e, and 9P.original. Preserve 9P's central model: attach to a namespace, obtain fids, walk names, read and write resources, and release references. Support synthetic files and services as first-class resources, not merely disk files. 9P.original (editions 1 through 3) is a distinct pre-version wire format, supported through its own codec like the other legacy dialects.

Use one new dialect, `9Pfrank`, with explicit capability negotiation. The core implements one unified operation set: the semantic union of every dialect's operations. Everything that is not 9Pfrank is a codec that translates its wire protocol to 9Pfrank underneath, which is straightforward because 9Pfrank is a superset. Wire formats stay per-dialect and are not reinterpreted; what is unified is the semantics, not the bytes. Where a dialect differs structurally, the codec performs a small, documented translation rather than requiring the native set to mirror it; for example, 9P2000 `Tcreate` turns the directory fid into the new file's fid, and legacy partial walks remain a codec behavior. The rules in this document bind 9Pfrank proper; each legacy codec speaks its dialect as that dialect defines it, including its own transport and authentication.

The full filesystem implementation should provide all applicable predecessor operations. Small synthetic servers may advertise a smaller profile. Unsupported backend features must produce explicit errors; they must never succeed without providing the promised behavior. “9Pfrank core” and “9Pfrank full filesystem” are distinct conformance claims.

Recommended initial deployment: persistent TLS 1.3 over TCP, a userspace client and server, bounded pipelining, compound metadata operations, and conservative caching. Add reconnect recovery and coherent caching only after correctness and measurements justify them. WireGuard is an excellent deployment option where an encrypted host network already exists. The reference implementation is written in C99, which builds across all major open-source distributions. It is a userspace library and server, so the OpenBSD kernel's language level does not constrain it; kernel portability, if pursued later, is a separate goal. The library uses a no-macro style: `#define` is permitted only for header guards; all constants are `const` or `enum`. Under C99 a `const` object is not a constant expression, so enum constants carry the array sizes and `case` labels; and because enum constants must fit in `int`, the u64 masks and limits are `static const` objects rather than enum members. It exposes a stable C ABI: a single public C99 header, using the standard `#ifdef __cplusplus`/`extern "C"` guard so C++ consumers link with C linkage, as the FFI surface.

## 2. What is being unified

| Heritage | Keep | Change in 9Pfrank |
| --- | --- | --- |
| 9P.original (editions 1–3) | The pre-version attach/walk/read/write/clunk model | A separate codec for a distinct wire format: no `Tversion`, fixed names and stat records, p9sk1/DES authentication |
| 9P2000 | Namespaces, fids, tag multiplexing, walk, auth files, synthetic resources, flush | Larger fids and a monotonic session sequence replacing the small tag; explicit lifetimes, bounds, ordering, and cancellation outcomes |
| 9P2000.u | Unix object kinds, ownership, special mode bits, human-readable errors | Typed metadata rather than overloaded extension strings; identity domains rather than implicit global UID agreement |
| 9P2000.L | POSIX-oriented open/create, metadata, directory iteration, links, xattrs, locking, fsync, statfs | Protocol-owned flags and error codes; portable device numbers; precise durability and lock ownership |
| 9P2000.e recovery/shortcut lineage | Reconnectable sessions and fewer round trips for small files | Authenticated session resumption, bounded duplicate suppression, general ordered compounds |
| Other experience | Conditional updates, sparse files, server-side copy, notifications, strong cache invalidation, safe path resolution | Negotiated modules with explicit semantics, not mandatory distributed-system machinery in every server |

9P2000.u adds numeric identity fields and Unix metadata extensions. Its published draft also contains unfinished sections, so compatibility needs implementation fixtures in addition to prose. [9P2000.u draft](https://ericvh.github.io/9p-rfc/rfc9p2000.u.html)

9P2000.L supplies the filesystem-oriented operations above and uses Linux-specific error conventions. Preserve their functionality while defining the new dialect independently of a host ABI. [diod protocol documentation](https://github.com/chaos/diod/blob/master/protocol.md)

9P.original (editions 1 through 3) is a distinct pre-version wire format: no size prefix, a 2-byte tag per message, sessions open with `Tnop`/`Tsession`, names and stat records are fixed-size (28 and 116 bytes), and authentication is in-band p9sk1 with DES. Every message has a size fixed by its type apart from the count-bearing `Twrite` and `Rread`, so its codec delimits messages itself over any stream transport. The codec reports OVERFLOW for anything that does not fit its 32-bit qid paths (31 usable after the CHDIR bit), 28-byte names, and u32 stat times (which overflow in 2038), and it caps I/O at the fixed 8192-byte data limit, since there is no negotiated `msize`.

p9sk1 is open to offline dictionary attack, so the default policy is to serve it only over an authenticated transport and let the transport identity, not p9sk1, authorize access. A server with no DES key declines the ticket exchange; whether a 1st-3rd edition client then proceeds unauthenticated (`none`) is to verify in Phase A. Registering a DES key with a Plan 9 auth server is a deployment prerequisite only if p9sk1 must actually be served. The old `Tattach` `uname[28]` is not trusted as-is; local policy maps it to an identity. The exact framing is pinned in Phase A.

### 2.1 The `.e` dialect

9P2000.e adds session restoration and compound ("macro") operations on top of 9P2000. It is specified by the Erlang on Xen extension spec, which documents an 8-byte `Tsession` key, all fids preserved on reestablishment, and graceful fallback to plain 9P2000. [Erlang on Xen extension spec](https://erlangonxen.org/more/9p2000e), [qp package documentation (unverified)](https://pkg.go.dev/github.com/csdksoftware/qp), [LING implementation documentation (unverified)](https://github.com/cloudozer/ling/blob/master/doc/9p.md)

Its session restoration uses an unauthenticated 8-byte session key in `Tsession`: the key identifies which retained session to resume, but does not authenticate the client. It preserves fids across reestablishment but offers no replay or duplicate suppression, so a `.e` codec provides resumption without 9Pfrank's replay guarantees. 9Pfrank's `resume_proof` is bound to the authenticated principal and the session.

9Pfrank preserves these capabilities natively: session resumption, bounded duplicate suppression, and ordered compounds. LING's Erlang-specific authentication and internode messaging are a separate concern, handled by a separately named adapter module rather than the `.e` wire protocol.

## 3. Compatibility and connection startup

1. Native 9Pfrank traffic establishes the configured authenticated transport **before** any 9P bytes, except in the debug mode. The server has three listeners. The TLS port expects a TLS ClientHello first and, after the handshake, runs step 2 detection, which selects `9Pfrank` or a TLS-wrapped legacy codec. The raw codec port carries plaintext, where step 2's byte-0 dispatch selects the 9P2000 family or 9P.original, and where native `9Pfrank` is accepted only when the debug knob is on. The 9front port runs dp9ik pre-auth then TLS-PSK and accepts only the 9P2000 codec.
2. Byte 0 selects the path first: `Tnop` or `Tsession` dispatches to the original-9P codec immediately. Otherwise read 13 bytes and require a self-consistent `Tversion` (type 100 at offset 4, `size` equal to 13 plus the version-string length); anything else is dropped. The checks do not collide: a `Tversion`'s byte 0 is the low byte of its size, which equals `Tnop` or `Tsession` only for version strings whose length is 37 or 71 modulo 256, lengths no accepted dialect uses. On the version path, the server matches the client's `version` string exactly to select a codec: `9P2000`, `9P2000.u`, `9P2000.L`, and `9P2000.e` select their legacy codecs; `9Pfrank` selects the native codec. Any other version string is handled per version(5): strip a `.suffix`, require `9P` followed by digits; if the digits are at least 2000, reply `9P2000`, otherwise reply `unknown`.
3. A native client sends `version="9Pfrank"`, tag `0xffff`, and a proposed maximum message size. Any reply other than exactly `9Pfrank` means the server does not speak the native dialect, so in-place downgrade to 9P2000 is impossible; a native client that must fall back to a legacy dialect opens a fresh connection and sends that dialect's own version string.
4. An exact `9Pfrank` reply switches both directions to the native header immediately after that reply. Then exchange HELLO; no attach or filesystem operation is legal before HELLO completes.
5. By default, a 9Pfrank server accepts 9P2000, 9P2000.u, 9P2000.L, 9P2000.e, and 9P.original clients. Local policy may restrict the permitted set; a dialect outside it is disconnected. A compatibility retry uses a fresh connection and the exact selected legacy codec. A native client that falls back keeps its configured transport: fallback changes the dialect, not the transport, so a TLS or tunnel requirement still holds.
6. There is one version exchange per transport connection. Mid-session reset requires a new connection; this removes a dangerous interaction between reset, active operations, and recovery.

```text
# Legacy bootstrap only; little-endian integers, no padding.
Tversion = size:u32 type:u8=100 tag:u16=65535 msize:u32 version:str16
Rversion = size:u32 type:u8=101 tag:u16=65535 msize:u32 version:str16
str16    = length:u16 bytes:u8[length]
```

The legacy envelope and version-negotiation mechanism come from 9P2000. The post-reply switch is new. The returned `msize` includes the 9P frame header, excludes transport overhead, and cannot exceed the client's offer. Require at least 4096 bytes for 9Pfrank. [9P2000 version specification](https://ericvh.github.io/9p-rfc/rfc9p2000.html)

Never advertise 9Pfrank support merely because a server accepts `.L`. Legacy codecs retain legacy qids, flag values, stat encodings, partial-walk semantics, and remove/clunk behavior. They must report overflow when new identities, timestamps, sizes, or IDs cannot be represented. Legacy qid translation needs a collision-free mapping for the codec's advertised lifetime; truncating an object ID is insufficient.

## 4. Exact encoding conventions

These declarations describe wire bytes, **not** compiler C struct layout. There is no implicit alignment or padding. Implement fieldwise codecs; do not cast a packet buffer to a host struct.

```text
u8/u16/u32/u64 = unsigned little-endian integers of 1/2/4/8 bytes
s64           = signed two's-complement little-endian, 8 bytes
id128         = opaque 16 bytes; compare as bytes, not as a UUID integer
blob          = length:u32 data:u8[length]
text          = blob containing valid UTF-8, without NUL
name          = blob containing filesystem name bytes
array<T>      = count:u32 items:T[count]
Time          = seconds:s64 nanoseconds:u32                 # 12 bytes
TLV           = type:u16 flags:u16 length:u32 value:u8[length]
Ext           = byte_length:u32 records:TLV[...]            # exact byte budget
```

`Time` is POSIX time relative to 1970-01-01 UTC; nanoseconds are 0..999,999,999. It is not a monotonic timer and carries no leap-second representation. Protocol timeouts use monotonic durations, never wall-clock timestamps.

A name is nonempty and contains neither slash nor NUL. Mutation names (CREATE, LINK, RENAME, UNLINK targets) may not be `.` or `..`. Walk components may be `.` (a no-op that returns the current ref) or `..` (the parent, clamped at the attach root); root itself is represented by a fid. Names are byte-preserving, not implicitly Unicode-normalized or case-folded. Exports report their own naming constraints. Symlink targets are blobs, may contain slash, and may not contain NUL. Text identities and diagnostics are separate from filesystem names.

All lengths must fit the remaining frame, negotiated limits, and checked arithmetic before allocation. A count does not authorize an allocation proportional to an untrusted maximum. Unknown mandatory TLVs (`flags & 1`) fail with UNSUPPORTED; optional unknown TLVs are skipped. Other TLV flag bits are reserved. Duplicate TLV types are invalid unless that type explicitly permits repetition. Core operations end in `Ext`, empty when unused; unknown trailing bytes outside it are invalid.

### 4.1 Native frame

```text
Frame {
    size:       u32;     # includes this field; minimum 20
    opcode:     u16;
    flags:      u16;     # RESPONSE=1; other bits zero in revision 1
    sequence:   u64;     # request identity; responses echo it
    reserved:   u32;     # MUST be zero
    body:       u8[size - 20];
}                       # fixed header = 20 bytes
```

Responses echo opcode and sequence. Every response body begins with `Result`. Every request has a nonzero, monotonically allocated session sequence; clients may transmit them out of order. Never reuse a sequence in a session, including after reconnect. No unsolicited server frames in revision 1; notification delivery uses a pending request.

```text
Result {
    status:          u32;    # 0 = success
    effect:          u8;     # 0 NONE, 1 COMPLETE, 2 PARTIAL, 3 UNKNOWN
    reserved:        u8[3];  # zero
    retry_after_ms:  u32;    # advisory backoff, zero if absent
    diagnostic:     text;   # bounded to 1024 bytes; never machine-parsed
    details:        Ext;
}
# On status=0: operation-specific success fields follow Result.
# On status!=0: no success fields; progress belongs in typed details.
```

`effect` describes externally visible side effects, not whether bytes reached the network. Pure reads of regular files use NONE; consuming reads of synthetic resources may have effects. A valid error is not automatically safe to retry. Unknown or partial mutation outcomes must reach the application or recovery logic.

Proposed error registry, independent of libc: OK=0, PERMISSION=1, NOT_FOUND=2, EXISTS=3, NOT_DIR=4, IS_DIR=5, INVALID=6, UNSUPPORTED=7, IO=8, NO_SPACE=9, QUOTA=10, READ_ONLY=11, BUSY=12, STALE=13, AGAIN=14, CONFLICT=15, CANCELLED=16, TOO_LARGE=17, AUTH=18, SESSION_LOST=19, REPLAY_EXPIRED=20, OUTCOME_UNKNOWN=21, CROSS_DEVICE=22, NOT_EMPTY=23, LOOP=24, OVERFLOW=25, BAD_FID=26, RESOURCE_LIMIT=27, RANGE=28, NO_DATA=29, BAD_COOKIE=30. Reserve 31..4095 for future standard errors, 4096..65535 for registered extensions. The freeze deliverable includes exhaustive errno mappings, including a generic IO fallback for unknown codes; diagnostic text never changes control flow. The 9P2000 codec maps these codes to the canonical Plan 9 error strings existing programs match (for example NOT_FOUND to "file does not exist").

### 4.2 HELLO and limits

```text
Limits {
    max_frame:          u32;
    max_inflight:       u32;
    max_fids:           u32;
    max_io:             u32;
    max_compound_ops:   u32;
    max_name:           u32;
    max_walk:           u32;
    max_xattr:          u32;
    max_inflight_bytes: u64;
}
Feature { id:u16 min_revision:u16 max_revision:u16 reserved:u16=0; }
T_HELLO {
    client_instance:id128;  # random per client process incarnation
    resume_session:id128;  # all zero for new session
    resume_proof:blob;      # opaque token; empty for new session
    limits:Limits;
    features:array<Feature>;
    required:array<u16>;
    ext:Ext;
}
R_HELLO {                  # following Result
    server_instance:id128; # changes whenever retained session state is lost
    session:id128;
    connection_epoch:u64;
    resume_proof:blob;
    retention_ms:u32;
    replay_slots:u32;
    replay_bytes:u64;
    limits:Limits;
    features:array<Feature>; # one exact revision each: min=max
    ext:Ext;
}
```

The server chooses limits no greater than the client's offer or its own policy; `max_frame` is also capped by bootstrap `msize`. Mandatory features that cannot be selected fail HELLO. Unselected feature opcodes fail UNSUPPORTED. Selection is immutable within a retained session; resumption offers must admit its previous selection. New connections may reduce frame/transport limits only if cached replies remain deliverable; otherwise resumption fails explicitly.

Starting policy, to benchmark rather than canonize: 1 MiB frames, 256 KiB I/O, 128 in-flight requests, 32 MiB in-flight request bytes, 8192 fids, 32 compound members, 255-byte names, 64 walk components, and 64 KiB xattrs. Reserve several request slots for cancellation, recovery acknowledgments, and lease traffic. Also bound queued reply bytes, handshakes, principals, attaches, subscriptions, and per-export resource consumption. Client and server apply independent memory budgets.

Feature IDs: CORE=1, POSIX=2, XATTR=3, LOCK=4, COMPOUND=5, RECOVERY=6, WATCH=7, LEASE=8, SPACE=9, COPY=10, AUTHFILE=11, PLAN9_META=12, ACL_POSIX=13. CORE revision 1 is required; the full filesystem profile requires 1..7, 9..13 where the backend supports their semantics, and explicitly reports backend limitations. LEASE is optional; correct uncached operation remains possible.

### 4.3 Identity, fids, and attributes

```text
Principal {
    authority:text;        # administratively configured identity domain
    subject:text;          # canonical account/group within that domain
    numeric_valid:u8;      # 0 or 1
    numeric_id:u64;        # zero if numeric_valid=0; local mapping hint only
}
ObjectID {
    filesystem:id128;
    object:id128;
    generation:u64;
}                          # 40 bytes
ObjectRef {
    id:ObjectID;
    kind:u8;
    change_valid:u8;       # 0 or 1
    reserved:u16=0;
    change:u64;
}                          # 52 bytes
Attributes {
    valid:u64;               # always present; bits 0..13 select trailing fields
    ref:ObjectRef;           # always present; object identity
    # Trailing fields, present only when their valid bit is set, in this order:
    mode:u32;               # bit 0; Unix permission/special bits only: 0..07777
    owner:Principal;        # bit 1
    group:Principal;        # bit 2
    nlink:u64;              # bit 3
    size:u64;               # bit 4
    allocated_bytes:u64;    # bit 5
    preferred_io:u32;       # bit 6
    device_major:u32;       # bit 7
    device_minor:u32;       # bit 7
    atime:Time;             # bit 8
    mtime:Time;             # bit 9
    ctime:Time;             # bit 10
    btime:Time;             # bit 11
    plan9_flags:u64;        # bit 12
    last_modifier:Principal; # bit 13
    ext:Ext;                # always present; empty when unused
}
```

Kinds: REGULAR=1, DIRECTORY=2, SYMLINK=3, CHAR_DEVICE=4, BLOCK_DEVICE=5, FIFO=6, SOCKET_NODE=7, SERVICE=8, AUTH=9. A socket node does not imply remote socket-connect support. `plan9_flags`: APPEND_ONLY=1, EXCLUSIVE_OPEN=2, MOUNT_POINT=4, TEMPORARY=8. These flags need documented server enforcement; TEMPORARY is a storage hint, not automatic deletion.

Attribute validity bits 0..14 select, respectively: mode, owner, group, nlink, size, allocated_bytes, preferred_io, device pair, atime, mtime, ctime, btime, plan9_flags, last_modifier, stable identity. `valid` and `ref` are always present; a selected trailing field (bits 0..13) follows in bit order and an unselected one is omitted. Bit 14 (stable identity) qualifies `ref` and adds no trailing field; the change counter is signalled by `ref.change_valid`. Unknown validity bits are rejected in requests, ignored in responses. The object kind is always meaningful.

Fids are nonzero `u64`, scoped to one session, allocated by the client. No second operation may claim an existing fid. An object's identity is separate from a particular open reference. A generation changes before reusing an object number. An export that cannot guarantee persistence must clear stable-identity validity; it still needs unique live-session identities. Identity alone does not grant access or reopen authority.

`change` is an opaque monotonically increasing `u64` within one object generation; it advances for data, relevant metadata, and directory-entry changes. Before wrapping, change generation and invalidate affected handles/caches. Servers unable to observe external backend writes must not claim reliable change counters or coherent leases. Access-time maintenance is excluded from the counter to avoid reads invalidating themselves.

Authentication establishes an allowed principal set. A UID/GID in a packet never proves identity. Fids inherit the authorized principal and export of their attach; operations cannot swap credentials. Group memberships are server-validated. A trusted multiuser gateway requires explicit impersonation authority; a machine certificate alone is insufficient.

## 5. Operations and proposed native bodies

Opcode numbers below are proposed native numbers, unrelated to legacy numbers. `T` and `R` use the same opcode with the RESPONSE flag. `R` entries below omit their leading `Result`. Every listed T/R body ends with `ext:Ext`, even when omitted below for readability. Empty `R` therefore contains `Result` and an empty `Ext`.

```text
01 HELLO        # Section 4.2
02 ATTACH  T { newfid:u64 export:text requested:Principal authfid:u64 }
           R { root:ObjectRef attrs:Attributes }
03 WALK    T { fid:u64 newfid:u64 components:array<name> }
           R { refs:array<ObjectRef> }
04 OPEN    T { fid:u64 access:u8 flags:u32 }
           R { ref:ObjectRef max_io:u32 }
05 CREATE  T { dirfid:u64 newfid:u64 name:name kind:u8 mode:u32
               group:Principal access:u8 flags:u32 plan9_flags:u64
               target:blob device_major:u32 device_minor:u32 }
           R { ref:ObjectRef attrs:Attributes max_io:u32 }
06 READ    T { fid:u64 offset:u64 count:u32 }
           R { data:blob eof:u8 change_valid:u8 change:u64 }
07 WRITE   T { fid:u64 offset:u64 stability:u8 data:blob }
           R { count:u32 actual_offset:u64 stability:u8
               change_valid:u8 change:u64 }
08 CLUNK   T { fid:u64 } R { }
09 GETATTR T { fid:u64 mask:u64 } R { attrs:Attributes }
10 SETATTR T { fid:u64 update:AttrUpdate }
           R { attrs:Attributes }
11 READDIR T { fid:u64 cookie:blob max_bytes:u32 attr_mask:u64 }
           R { eof:u8 entries:array<DirEntry> }
12 READLINK T { fid:u64 } R { target:blob }
13 LINK    T { sourcefid:u64 dirfid:u64 name:name } R { }
14 RENAME  T { olddir:u64 oldname:name newdir:u64 newname:name flags:u32 }
           R { }
15 UNLINK  T { dirfid:u64 name:name flags:u32 } R { }
16 REMOVE  T { fid:u64 } R { }
17 FSYNC   T { fid:u64 flags:u32 } R { }
18 STATFS  T { fid:u64 } R { info:FSInfo }
19 CANCEL  T { target_sequence:u64 }
           R { disposition:u8 }
20 AUTH    T { newfid:u64 method:text requested:Principal export:text }
           R { ref:ObjectRef }
21 XATTR   T { fid:u64 action:u8 name:blob value:blob max_bytes:u32 flags:u32 }
           R { value:blob names:array<blob> required_bytes:u32 }
22 LOCK    T { fid:u64 owner:id128 action:u8 kind:u8 start:u64 length:u64 }
           R { granted:u8 conflict:LockConflict }
23 COMPOUND # Section 6
24 ACK     T { through_sequence:u64 } R { }
25 WATCH   T { fid:u64 mask:u32 recursive:u8 }
           R { subscription:u64 next_event:u64 }
26 EVENTS  T { subscription:u64 after_event:u64 max_bytes:u32 wait_ms:u32 }
           R { overflow:u8 events:array<Event> }
27 UNWATCH T { subscription:u64 } R { }
28 SPACE   T { fid:u64 action:u8 offset:u64 length:u64 }
           R { offset:u64 }
29 COPY    T { sourcefid:u64 source_offset:u64 destfid:u64 dest_offset:u64
               length:u64 flags:u32 }
           R { copied:u64 }
30 LEASE   # Section 8; deferred until its state machine is proven
```

Any mutation can fail for an unsupported backend operation. Read-only exports can conform by rejecting writes with READ_ONLY. Unsupported object kinds use UNSUPPORTED. Error paths must release all unpublished temporary fids/resources.

### 5.1 Supporting records

```text
AttrUpdate {
    mask:u64;              # Attributes.valid bits, only settable ones accepted:
                           # mode=0 owner=1 group=2 size=4 atime=8 mtime=9 plan9_flags=12
    conditional:u8;        # 0 or 1
    expected_change:u64;   # zero when unconditional
    # Selected fields, present only when their mask bit is set, in bit order:
    mode:u32;             # bit 0
    owner:Principal;      # bit 1
    group:Principal;      # bit 2
    size:u64;             # bit 4
    atime_mode:u8;        # bit 8: 0 EXPLICIT, 1 SERVER_NOW
    atime:Time;           # bit 8
    mtime_mode:u8;        # bit 9
    mtime:Time;           # bit 9
    plan9_flags:u64;      # bit 12
}
DirEntry {
    name:name;
    next_cookie:blob;
    attrs:Attributes;      # sparse Attributes; kind is attrs.ref.kind
}
FSInfo {
    filesystem:id128;
    valid:u64;             # bits 0..7 select each following numeric field
    total_bytes:u64;
    free_bytes:u64;
    available_bytes:u64;   # available to this principal
    total_objects:u64;
    free_objects:u64;
    max_file_size:u64;
    max_name:u32;
    allocation_unit:u32;
    flags:u64;             # READ_ONLY=1 CASE_SENSITIVE=2 CASE_PRESERVING=4
    type_name:text;
}
LockConflict {
    present:u8;
    kind:u8;
    start:u64;
    length:u64;            # zero means through EOF
    owner:id128;
}                          # zero all remaining fields when present=0
Event {
    sequence:u64;
    kind:u16;              # CREATE=1 REMOVE=2 RENAME=3 MODIFY=4 ATTR=5
                           # DELETE_SELF=6 LEASE_RECALL=7
    object:ObjectRef;
    parent:ObjectID;
    name:blob;
    other_parent:ObjectID; # zero except RENAME
    other_name:blob;       # empty except RENAME
    lease_id:u64;          # zero except LEASE_RECALL
}
```

Unselected update fields are omitted, and mask bits for non-settable fields are rejected. When `atime_mode` or `mtime_mode` is SERVER_NOW, the following `Time` is still present, zero on send and ignored on receipt. A conditional SETATTR compares and updates atomically relative to all relevant backend writers or fails UNSUPPORTED. A failed comparison returns CONFLICT with no changes. Arbitrary multi-field SETATTR is not promised transactional: a backend that cannot roll back must return PARTIAL plus a details TLV `type=1, value=applied_mask:u64` when some changes preceded failure. Implementations should validate first and reduce partial outcomes.

### 5.2 Essential semantics and flags

- **Walk:** all-or-nothing native walk; zero components clones an unopened reference. A `.` component is a no-op returning the current ref; a `..` component moves to the parent, clamped at the attach root, and cannot escape the export boundary; `..` from an unlinked directory returns STALE. Success returns one ref per component, zero refs for a clone. No implicit symlink following. Clients read symlink targets and resolve explicitly within their namespace, with a configured link limit. The export boundary cannot be escaped through backend symlinks or mount races. Legacy partial walks remain a codec behavior.
- **Open/create:** access NONE=0, READ=1, WRITE=2, READ_WRITE=3, EXEC=4 (a bit, combinable: READ_EXEC=5, WRITE_EXEC=6, READ_WRITE_EXEC=7). EXEC alone requests the execute-permission check with no data access; on a directory it means search access. 9P2000 `OEXEC` maps to READ_EXEC. OPEN rejects NONE. Open flags: APPEND=1, TRUNCATE=2, EXCLUSIVE=4, NONBLOCK=8, REMOVE_ON_CLUNK=16, DIRECTORY_ONLY=32. EXCLUSIVE is valid only for CREATE. CREATE atomically creates or opens a regular file; EXCLUSIVE fails on existence. CREATE also takes `plan9_flags`, applied atomically at creation so APPEND_ONLY and EXCLUSIVE_OPEN take effect with no intervening open; with EXCLUSIVE_OPEN and a nonzero access, the creator's own open is the exclusive open. Other kinds require EXCLUSIVE and access NONE. A newly created regular file with access NONE returns an unopened fid. The parent fid never changes. Invalid combinations fail before mutation. `mode` is the final requested permission mask after client umask; the server may restrict it under export policy/default ACLs. Setgid inheritance overrides requested group where required.
- **Append:** the server chooses the EOF and writes atomically with respect to other append writes to that object. Replies give the actual offset; a client read-EOF/write sequence is not a substitute. Report unsupported if the backend cannot provide this guarantee. APPEND_ONLY applies across all opens; flags cannot bypass it.
- **I/O:** offsets use byte positions for regular files. SERVICE resources document whether offsets matter and whether reads consume state. Partial writes return the accepted byte count; partial failure details use TLV type 2 with `count:u32 actual_offset:u64`. Empty writes are not a synchronization primitive. Returned data must fit both `max_io` and the actual encoded response budget. `eof=1` means observed end of resource, not “short read.”
- **Durability:** WRITE stability 0=ACCEPTED, 1=DATA_STABLE, 2=FILE_STABLE. A success must meet the requested level; ACCEPTED may be volatile. FSYNC flags DATA_ONLY=1; zero means file data and required metadata. Directory FSYNC commits directory entries if supported. Durable replacement requires writing/syncing the temporary file, renaming, and syncing the relevant parent directories. CLUNK is not fsync. A storage backend must honor hardware flush guarantees before claiming stable completion.
- **Lifetime/order:** a successful CLUNK releases the fid. REMOVE_ON_CLUNK requires an unambiguous server-held directory-entry reference; refuse it if safe semantics cannot be implemented. Operations referencing one fid are executed in request-admission order on the initial TCP transport; assigning `newfid` (WALK, CREATE, AUTH) counts as referencing, so WALK(newfid=5) is ordered before any later operation on fid 5. Different fids can race, including aliases of one object. A client waits for writes before sending an fsync that must include them. CLUNK waits for earlier uses of that fid. Compound ordering is explicit. Do not infer application intent from numeric sequence gaps.
- **Directory iteration:** empty cookie starts an iteration; every entry supplies the next opaque cookie, bound to that directory, authorization view, and iteration generation. Return complete entries only. An empty non-EOF result is prohibited: return TOO_LARGE if one entry cannot fit. Mutation may invalidate iteration and return BAD_COOKIE; no snapshot guarantee unless a future feature explicitly supplies it. READ on a directory returns IS_DIR; codecs serialize legacy stat records when necessary.
- **Rename/unlink/remove:** RENAME flags NOREPLACE=1, EXCHANGE=2, mutually exclusive; zero permits replacement. Atomic visibility is required; unsupported exchange fails. Cross-filesystem rename fails CROSS_DEVICE. UNLINK flags DIRECTORY=1; zero unlinks a non-directory. Native unlink never clunks an unrelated open fid. REMOVE removes the object its fid names without releasing the fid. It corresponds to `Tremove`; the 9P2000 codec also releases the fid, as `Tremove` requires even on failure. The fid must hold the directory entry it was walked through, as REMOVE_ON_CLUNK does; REMOVE fails STALE when that entry no longer names the object. The attach root cannot be removed, and removing a non-empty directory returns NOT_EMPTY. Open-unlinked regular files remain accessible until references close, subject to backend support.
- **Xattrs:** action GET=0, SET=1, LIST=2, REMOVE=3. SET flags CREATE_ONLY=1, REPLACE_ONLY=2, mutually exclusive. LIST returns an array of names, not NUL packing. GET/LIST with max_bytes=0 performs a size query; `required_bytes` counts the encoded value blob or names array respectively. Too-small nonzero budgets return TOO_LARGE with required size (details TLV type 3, `required_bytes:u32`). Unused request/response fields are empty/zero. Large streaming xattrs are a future revision; never silently truncate. Security/trusted namespaces require separate authorization.
- **ACLs:** ACL_POSIX revision 1 uses xattr names `system.posix_acl_access` and `system.posix_acl_default`, with a protocol-owned value: `version:u16=1 count:u32 entries[count]`, each entry `tag:u8 permissions:u8 principal:Principal`. Tags USER_OBJ=1, USER=2, GROUP_OBJ=3, GROUP=4, MASK=5, OTHER=6; permissions READ=4, WRITE=2, EXECUTE=1. Non-named entries have empty principals. Validate uniqueness and required entries; default ACLs apply only to directories. The final specification must pin chmod/mask and inheritance rules with conformance fixtures. Do not label this NFSv4 or Windows ACL support; those require a different module with explicit translation-loss reporting.
- **Locks:** action TEST=0, TRY=1, UNLOCK=2; kind READ=1, WRITE=2. Locks are advisory byte-range locks, owned by `(session, owner)`, not an untrusted PID or hostname. A failed TRY returns success with granted=0 and a conflict if disclosable. Ranges use checked addition; zero length means through future EOF. Splits/merges and read-to-write replacement are atomic. For UNLOCK, kind=0. No blocking lock queue in revision 1: clients back off and retry. Clunk does not implicitly release owner locks; clients explicitly unlock, and session expiry releases all. POSIX clients must translate close/fork/dup semantics into these owner operations; flock uses a distinct owner or an explicitly documented interoperability policy. Mandatory locking is unsupported.
- **Cancellation:** disposition NOT_STARTED=0, FINISHED=1, MAY_HAVE_EFFECT=2, NOT_FOUND=3. A client MUST NOT send CANCEL before its target, including on resume, where retransmits precede cancels; the client controls transmit order and TCP preserves it. A CANCEL reply comes only after the target's terminal reply has been serialized. No later target response follows it. Cancelling a write does not roll it back. Cancellation of CANCEL is invalid; preserve reserved control capacity. The client keeps the target sequence outstanding until its terminal response or terminal connection failure.
- **SPACE/COPY:** SPACE actions ALLOCATE_KEEP_SIZE=0, PUNCH_HOLE_KEEP_SIZE=1, SEEK_DATA=2, SEEK_HOLE=3; length=0 for seeks. Allocation and punching return offset=0. COPY flags=0 in revision 1; it may return partial progress. Reject overlapping same-object ranges. Neither operation implies snapshots or durable completion. Missing backend support is explicit; clients may choose their own fallback.
- **Auth files:** AUTH creates a negotiated-method fid; READ/WRITE exchange method-defined bounded records. ATTACH uses authfid=0 for transport identity, or a completed auth fid otherwise. AUTHFILE methods must bind their result to this secure session/export; never accept credentials on an unencrypted network connection.

Factotum is Plan 9's secret-custody agent: a per-user process that holds the user's keys, passwords, and certificates and performs authentication on behalf of other programs, none of which ever sees the secret material. It presents a file interface mounted at `/mnt/factotum` (`ctl`, `needkey`, `proto`, `log`); a program that must authenticate asks factotum to run the appropriate protocol, and factotum returns only the resulting proof. It reaches 9P through the auth-file flow: factotum opens the connection, issues `Tauth` with an auth fid, exchanges the protocol messages over that fid, and the authenticated fid is carried into `Tattach` by the requesting program. Factotum is therefore the client-side driver of a mechanism 9P already defines: the wire protocol owns the fid exchange, factotum owns the secret.

9Pfrank keeps that mechanism (`AUTH`/`ATTACH`/`authfid`) method-agnostic (`method:text` and method-defined bounded records), so a factotum-like agent drives it unchanged. On modern multi-user Unix the same custody role is filled by ssh-agent, gpg-agent, Kerberos credential caches, and OS keyrings; these differ from factotum in interface (a socket or D-Bus endpoint rather than a 9P-mounted file tree) but not in function, and any of them can drive the AUTH fid on the client's behalf. The transport default, `authfid=0`, is the TLS 1.3 client certificate (§9.1); `AUTHFILE` is the hook for methods a certificate cannot carry. Factotum-style secret custody is thus a client-side deployment component, not a wire-protocol feature: 9Pfrank specifies the fid-based auth exchange, not the local agent that performs it.

The client ships optional shims (support code that translates an existing source's interface into a bounded `AUTH` method) which drive the auth fid. Shims occupy two client-side slots and one server-side slot:

**Secret-custody agents (factotum's slot)** hold secrets and produce proofs, revealing no key material:

- **ssh-agent** (`SSH_AUTH_SOCK`): SSH key signatures over the session challenge.
- **gpg-agent**: OpenPGP/SSH keys and smartcards via its Assuan protocol.
- **Kerberos credential caches**: KCM and FILE/DIR ccache; obtains a service ticket for the export's principal.
- **D-Bus Secret Service**: GNOME Keyring and KDE Wallet backends.
- **macOS Keychain**: SecItem API.
- **Windows Credential Manager / CNG**: DPAPI-protected credentials and keys.
- **PKCS#11 tokens**: smartcards, YubiKey, HSMs, SoftHSM.
- **TPM 2.0**: hardware-protected keys (optional; platform attestation is a separate path).

**Auth methods (not custody)** run a flow that yields a proof, independent of where any secret lives:

- **OIDC/OAuth2**: browser/device flow against any IdP, including social sign-on (Google, GitHub, Apple, and similar), binding the returned token to this session.
- **TOTP**: RFC 6238 one-time codes; the shared secret is sourced from a custody agent or a hardware OATH token, and the server verifies the code.

**Server-side verifiers**: each shimmed method is verified by its native backend (authorized_keys, a KDC, an IdP token endpoint, or a TOTP verifier), and **PAM** is shimmed as a general verifier behind an export.

The number of factors is a property of the method, not the protocol: a method may chain several challenges (a certificate, a password, a TOTP code) inside its own bounded record exchange, and 9Pfrank treats the result as a single authenticated fid.

Each shim is optional, advertises only the capabilities it supports, and reports unsupported operations explicitly (§1). The transport certificate path (`authfid=0`, §9.1) needs no shim.

## 6. Compounds: reduce round trips without inventing transactions

```text
Subrequest { local_id:u32 opcode:u16 reserved:u16=0 body:blob; }
Subreply   { local_id:u32 opcode:u16 reserved:u16=0 body:blob; }
T_COMPOUND {
    temporary_fids:array<u64>;
    reply_budget:u32;
    operations:array<Subrequest>;
    ext:Ext;
}
R_COMPOUND {
    completed:u32;          # includes the first failed suboperation
    replies:array<Subreply>;
    ext:Ext;
}
```

Bodies use the ordinary operation encoding, including their Ext and, for subreplies, Result. Local IDs are nonzero and unique within the compound. A subrequest may refer to a fid created by an earlier member. Listed temporary fids must be initially unused and created only inside this compound; they are always clunked on termination. They cannot be referenced by concurrent external requests. To return a persistent fid, create one not listed as temporary.

Execute in list order and stop at the first failed operation. No nesting; no HELLO, CANCEL, ACK, EVENTS, WATCH, or LEASE inside a compound. Prevalidate lengths, supported opcodes, fid dependencies, and worst-case encoded reply size before execution. If the bounded reply cannot fit the lesser of reply_budget and max_frame, reject before side effects. Enforce operation/CPU budgets. The outer Result reports whether a valid compound result exists; individual Results report operation outcomes. A failed prevalidation has no subreplies.

Example: `WALK(root, tmp, ["config"]), OPEN(tmp, READ), READ(tmp, 0, 4096)` with `tmp` temporary performs a small-file fetch in one RPC after attach. A directory READDIR with attributes avoids one getattr per child. These are usually better latency improvements than changing ciphers.

Compounds provide ordered execution, not isolation or rollback. Concurrent clients can observe intermediate results. Use EXCLUSIVE CREATE, atomic RENAME, and conditional SETATTR for the guarantees they explicitly provide. A future transactional backend module requires its own commit/recovery specification.

## 7. Recovery, replay, and disconnection

RECOVERY revision 1 retains sessions **only while the same server incarnation remains alive**. It does not promise replay-safe continuation after server restart, disk rollback, or failover. Start with this honest boundary; durable replay journals can be designed later.

A resume token is an unpredictable, server-generated opaque value, bounded to 4096 bytes, carried only inside encryption and bound server-side to the original authenticated principal, export policy, session, and retention deadline. Reauthenticate transport on resume. Possession of the token alone is insufficient. Never put it in a mount URL, command-line argument, or logs.

Retained sessions keep fids, open state, locks, and a replay table:

```text
ReplayRecord {                  # server memory model, not additional wire data
    session:          id128;
    sequence:         u64;
    request_digest:   byte[16];  # fast 128-bit hash(opcode || exact request body)
    state:            enum { RUNNING, COMPLETE, UNKNOWN };
    encoded_result:   byte[];
    reserved_bytes:   u64;
}
```

Before executing an operation, reserve a replay slot and enough bounded reply storage. Retain the replies of every operation whose `effect` is not NONE, including consuming reads and errors, until acknowledged or session expiry; a server MAY instead re-execute an operation whose effect is NONE (a pure read) on replay rather than retaining its reply, which keeps bulk regular-file reads out of `replay_bytes`. Same sequence plus same body returns the retained result or joins the in-progress operation. Same sequence with different bytes is a protocol violation. Authentication and session identity are part of the table key; a digest is not an authenticator, so a fast 128-bit hash (not SHA-256) suffices.

ACK means the client has received and will never replay every ordinary sequence at or below `through_sequence`; sequence gaps count as intentionally abandoned. Never acknowledge past an unresolved operation. ACK is idempotent control traffic, consumes its own sequence but no retained replay slot, and must not cause an acknowledgment loop. The server keeps a compact acknowledged floor and rejects requests below it with REPLAY_EXPIRED. Exhausted unacknowledged capacity produces RESOURCE_LIMIT before execution; do not evict entries and later rerun mutations. Session expiry discards the entire session and makes resumption fail.

Resumption admits one active connection epoch. Fence the previous connection, stop its admission, and account for all admitted operations before completing HELLO on the new one. Retransmit outstanding requests with their original sequences and bodies. No filesystem operation on the new epoch may slip ahead of an unaccounted old operation. Conflicting concurrent resumes are rejected. Retention should initially be configurable, e.g. 60 seconds, with quotas and clear operator metrics; it is not a guaranteed outage tolerance.

If the server loses state after a backend write but before preserving its result, a new server incarnation returns SESSION_LOST. The client reports the unresolved mutation as OUTCOME_UNKNOWN. It must not blindly repeat append, create, rename, a synthetic control write, or a consuming read. Even a fixed-offset write can conflict with intervening writers. Resume transport encryption and resume filesystem state are different operations.

Lock state survives only a successful retained-session resume. Expired sessions lose locks; clients cannot keep advertising their old lock guarantees after reconnect. Durable lock reclaim, grace periods, persistent file handles, and cross-server failover are separate future work.

## 8. Caching and notifications

Ship the core with no persistent client data/attribute cache by default. Caching without a contract is a correctness bug for mutable shared files. Immutable snapshot exports may explicitly permit persistent caches keyed by export identity, object generation, authorization view, and snapshot identity.

WATCH/EVENTS provides bounded advisory change notification. `mask` uses bits 0..5 for event kinds 1..6; recursive is 0 or 1 and may be unsupported. Per-subscription event sequences start at 1. `after_event` is the last consumed sequence; delivery can repeat events after reconnect. Clients discard duplicates. An overflow sets overflow=1 and requires rescan; it never silently loses coherency. `wait_ms` is bounded by server policy. Authorization changes terminate or filter subscriptions without leaking inaccessible names.

Notifications alone do **not** authorize caching. LEASE is a later, separately gated revision with this proposed body:

```text
T_LEASE { action:u8 fid:u64 lease_id:u64 requested_ms:u32 ext:Ext; }
R_LEASE { lease_id:u64 granted_ms:u32 ref:ObjectRef ext:Ext; }
# action: ACQUIRE_READ=0, RENEW=1, RELEASE=2, ACK_RECALL=3
# ACQUIRE uses lease_id=0; other actions identify an existing lease.
```

Before a conflicting change becomes visible, a server recalls all affected read leases and waits for acknowledgments or safe expiry. The client invalidates its relevant caches before ACK_RECALL. This includes aliases, directory and negative-entry caches, and writable backend access outside 9P. A notification overflow or broken event channel invalidates every dependent lease. No writable delegation or client writeback lease in the first lease revision.

For expiry without synchronized clocks: a client measures its usable interval from monotonic request-send time, subtracting a specified drift/safety margin; the server retains exclusion for at least the granted interval after issuing the grant. A client whose grant arrives too late discards it. Freeze exact drift bounds and suspend/resume behavior before enabling this feature; invalidate on local suspend uncertainty. Lease reads cannot outlive valid exclusion. If external backend writers cannot participate in recalls, the export must refuse LEASE.

A strict-cache claim requires a complete lease state machine, model tests for races, and failover fencing. Until those exist, this module is experimental and disabled. Close-to-open behavior, if later offered, must have a separate name and contract; it is not full coherence.

## 9. Secure network mounts with reasonable latency and cost

### 9.1 Transport choices

| Deployment | Recommendation | Cost and limitations |
| --- | --- | --- |
| Native clients and servers | TLS 1.3 over persistent TCP as the initial default | Broad library support; one ordered byte stream has head-of-line blocking under packet loss |
| Managed fleet or existing VPN | TCP inside WireGuard, restricted to the tunnel | Efficient host-level encryption; peer identity still needs an explicit user/export mapping |
| Existing legacy clients | WireGuard or a supervised authenticated TLS/SSH tunnel | Requires no legacy protocol change; gateway copies, lifecycle, and identity delegation need care |
| 9front | dp9ik pre-auth, then TLS keyed with the resulting secret as PSK (`pskID = "p9secret"`) | A plaintext PAKE runs before TLS, and it negotiates TLS 1.2 PSK rather than TLS 1.3 |
| Local same-host connection | Unix socket with peer credentials and OS access controls | Avoids unnecessary network cryptography; does not cover another host or an untrusted VM boundary |

TLS 1.3 provides authenticated encryption, modern key establishment, resumption, and key updates. Disable TLS early data for all 9P application traffic: replayed “reads” can consume synthetic streams, and mount/auth actions can create state. Verify server identity and use client certificates or an explicitly authenticated application method. The recommended TLS profile supports TLS_AES_128_GCM_SHA256 and TLS_CHACHA20_POLY1305_SHA256; prefer based on actual endpoint acceleration and measurement. Never design new ciphers or disable integrity for speed. [TLS 1.3, RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)

WireGuard uses a defined authenticated key exchange and ChaCha20-Poly1305. It is a useful option for legacy 9P traffic, but its peer key identifies a peer, not every account on that peer. Bind the server to its tunnel address, firewall alternate paths, and map peers to tightly scoped export identities or require additional per-user authentication. [WireGuard protocol](https://www.wireguard.com/protocol/)

9front is accepted: the server offers the 9P2000 codec over dp9ik pre-auth plus TLS-PSK, which requires registration with a 9front auth server and its own port, because dp9ik sends plaintext before TLS while the native listener expects a TLS ClientHello first. The flow is `tlsclient -a` running `auth_proxy` with `proto=p9any` over the plain connection first, then TLS keyed with the resulting secret as a PSK. The TLS-1.3-only rule binds native 9Pfrank, not this codec, which speaks 9front's transport as it is. Three claims need verification: that 9front's libsec lacks TLS 1.3 client-certificate support, that it negotiates TLS 1.2 PSK rather than TLS 1.3, and that LibreSSL lacks the PSK cipher suites (the `openssl11` package name is from an old README and may be stale).

Choose one encryption boundary deliberately. TLS inside WireGuard can be appropriate for end-to-end process authentication or different administrative boundaries, but adds processing and packet overhead. Benchmark that choice. A tunnel terminating on a gateway protects only as far as that gateway unless the backend leg is also secured.

Plaintext is a debug mode for both 9Pfrank and the codecs, off by default and lab-only; the server enables it with its own knob, separate from the client's `allow_plaintext`. The TLS path never force-downgrades to it. Plaintext means a raw listener not bound to an authenticated tunnel interface or a local socket; a raw port on WireGuard or a Unix socket is not plaintext for this purpose. `9Pfrank` is a proposed ALPN identifier; check registration requirements before publication. Use configurable ports until service registration is settled.

### 9.2 Mount security policy

- Authenticate the server using a configured CA/name or pinned public key. Do not automate trust-on-first-use for unattended mounts. Rotate keys with overlap and revocation procedures. Keep private keys out of world-readable mount configuration.
- Authorize every attach against a configured export name. The client does not send an arbitrary server filesystem path. Export IDs resolve through an administrator-controlled table.
- Default to a single authorized user per workstation mount. Explicitly authorize multiuser gateways and root delegation. Numeric UID zero does not grant remote root.
- Enforce export boundaries using directory-relative backend operations and race-resistant resolution. Test symlinks, rename races, bind mounts, and special-file access. Avoid string-prefix path checks.
- Use `nodev,nosuid` for general remote data mounts. Use `noexec` when the workload does not require execution; it is defense in depth, not protection from an interpreter reading malicious code. Do not expose host devices or privileged xattr operations by default.
- Enforce authorization on the server even if a client kernel also checks permissions. Treat metadata, filenames, errors, and application bytes from the server as untrusted parser input.
- Bound reconnect attempts and request deadlines. A timeout is not proof of failure. Make uncertain writes visible; do not silently make a failed shared mount writable offline.
- Use scoped certificates/keys, handshake rate limits, per-principal quotas, and useful audit records. Log identity, export, operation class, latency, and outcome; redact secrets and avoid routine file-content logging.

Linux's documented 9P mount options currently list 9P2000, `.u`, and `.L`; they do not establish support for this proposed dialect or a native TLS transport. New kernel support or a userspace filesystem client is required for 9Pfrank. [Linux 9P documentation](https://docs.kernel.org/filesystems/9p.html)

Proposed **future** mount configuration; this is a design example, not a command supported by current mount utilities:

```toml
protocol = "9Pfrank"
transport = "tls-tcp"
server = "files.example.net:5640"  # deployment-chosen port, not a registration
export = "projects"
mountpoint = "/mnt/projects"
verify_name = "files.example.net"
ca_file = "/etc/9Pfrank/ca.pem"
client_certificate = "/etc/9Pfrank/workstation.pem"
client_key = "/etc/9Pfrank/workstation.key"
identity = "alice@example.net"
allow_legacy = false
allow_plaintext = false  # debug only
mount_options = ["nodev", "nosuid"]
cache = "none"
max_io = 262144
max_inflight = 128
max_inflight_bytes = 33554432
```

A legacy `.L` mount inside WireGuard is a migration bridge, not proof of 9Pfrank support. Document and test an OS-specific recipe once the server, identity model, firewall, and client implementation are selected; a generic mount command cannot establish those prerequisites.

### 9.3 Where performance will actually come from

Encryption cost is real but workload-dependent; there is no honest universal “less than X%” promise. Separate cryptographic CPU, memory copies, syscall overhead, storage latency, and network round trips. Avoid buying hardware before measuring those components.

Keep connections alive and pipeline independent operations. Do not open a TLS connection per file. Use compound lookup/open/read and readdir-with-attributes. Bound bulk chunks so control traffic is not stuck behind huge writes. Use fair queues; on a single TCP stream, bytes already sent cannot be reprioritized.

For a path requiring four serial RPCs on a 20 ms RTT link, the network component is approximately 80 ms. One compound reduces it to approximately 20 ms, excluding storage, transfer time, and scheduling. This is a model, not a measured result. At 1 Gbit/s and 20 ms RTT, the bandwidth-delay product is about 2.5 MB; 128 requests of 4 KiB provide only 512 KiB in flight. Tune byte windows as well as request counts.

Use scatter/gather I/O and bounded buffer pools. Assess TLS library record buffering; promptly send small interactive responses and batch bulk transfers without artificial waits. Evaluate TCP_NODELAY for metadata-heavy workloads. Kernel TLS or NIC offload is optional and must be measured end to end; neither automatically removes all copies. Choose AES-GCM on hardware where it performs well and ChaCha20-Poly1305 where that wins. Prefer maintained libraries and ordinary hardware before specialized accelerators.

No protocol compression in revision 1. It consumes CPU and complicates resource limits and confidentiality analysis; evaluate an explicitly negotiated future module only on representative compressible data. Avoid generic RPC-over-JSON or HTTP wrappers in the hot path unless operational requirements justify their overhead. Ethernet MTU is not the 9P message limit; let transport segmentation work and test tunnel path MTU rather than increasing packet size blindly.

### 9.4 Measurement and acceptance

Use the same filesystem, data, identity checks, caching policy, concurrency, machines, and path for each comparison. Record CPU model, crypto acceleration, kernel/library versions, storage, RTT, loss, and warm/cold cache state.

Compare isolated-lab plaintext TCP as a measurement baseline, TLS/TCP, and WireGuard/TCP. Never make the baseline an exposed production mode.

| Workload | Report |
| --- | --- |
| Small-file walk/open/read/close, stat storms | ops/s and p50/p95/p99 operation latency; compound vs serial |
| Directory enumeration, with and without attributes | RPC count, bytes, CPU, latency |
| Large sequential reads/writes | goodput, CPU-seconds/GiB on both ends, allocations, RSS |
| Random 4 KiB I/O at queue depths 1, 8, 32, 128 | IOPS, tail latency, achieved in-flight bytes |
| Concurrent metadata and bulk I/O | control latency and fairness under saturation |
| WAN simulation at 0.2/5/20/80 ms RTT and 0/0.1/1% loss | goodput and tails, disconnect behavior |
| Reconnect before/after mutation reply | duplicate effects, retained-state behavior, visible uncertainty |
| fsync and rename crash tests | durable outcomes and error reporting |

Provisional engineering targets, not promises: on hardware with adequate crypto capacity, TLS bulk goodput at least 90% of the otherwise identical plaintext path, metadata p99 no more than 10% worse once connected, and bounded memory at every tested load. Failure of a target triggers profiling, not weaker authentication or disabled encryption. Report absolute numbers beside percentages, especially on sub-millisecond LANs.

Estimate cost as measured CPU-seconds/GiB × projected volume plus peak required cores, memory per concurrent mount, and bandwidth/provider charges. Persistent connections amortize handshake cost. Small installations can use a simple managed CA or peer-key inventory; certificate automation and operational labor matter as much as cryptographic throughput. No paid overlay service is a protocol requirement.

### 9.5 Linux v9fs kernel client

The in-kernel v9fs client speaks 9P2000, `.u`, and `.L` today. Making it a native 9Pfrank client is a separate, phased effort:

1. Replace the 9P2000 wire codec with the 9Pfrank codec (20-byte header, native opcodes, fieldwise codecs).
2. Map VFS operations onto native operations: compounds for lookup/open/read, and readdir-with-attributes with sparse attributes.
3. Keep TLS out of the kernel. The mount connects over a local transport (Unix socket or loopback) to a userspace client that holds the TLS connection, or uses kTLS after a userspace handshake; the kernel speaks only 9Pfrank framing.
4. Keep 9P2000, `.u`, and `.L` support; native 9Pfrank is added alongside, not a replacement.
5. Gate: the kernel codec matches the userspace client byte-for-byte, and legacy 9P2000 mounts still pass their regression suite.

## 10. Delivery plan

### Phase A: evidence and semantic inventory

Produce pinned source references and wire fixtures for 9P2000, `.u`, `.L`, 9P.original, and each identified `.e` lineage. Inventory every legacy operation, flag, error, object type, and edge case in a coverage matrix. Add tests for old auth/stat encodings, numeric identity preference, partial walks, remove/clunk semantics, and the canonical 9P2000 error strings (Plan 9 programs match strings, e.g. NOT_FOUND to "file does not exist"). Review Plan 9 synthetic resource workloads, not only POSIX files.

Deliverables: `spec/legacy-coverage.md`, `spec/sources.lock`, captured/constructed golden packets, and explicit unsupported-backend cases.

### Phase B: freeze the core draft and codecs

Turn this plan into a normative grammar/IDL plus registries and a state-machine specification. Resolve all per-op invalid combinations, errno mappings, ACL rules, negotiated maxima, and frame-size formulas. Generate codecs or cross-check two handwritten codecs. Publish endian, signed-time, Unicode/name-byte, overflow, and error fixtures. Fuzz malformed/truncated frames, TLVs, count/length contradictions, sequence reuse, and fid reuse.

Gate: two independent codecs agree byte-for-byte, malformed inputs remain within bounded memory/CPU, and every draft field has defined validity and failure behavior.

### Phase C: useful secure prototype

Implement a userspace server and mount client with CORE, POSIX, TLS/TCP, and a local Unix-socket transport. Add legacy `.L` and `.u` codecs to the same backend API without merging them. Use explicit identity mapping and export confinement. Default to uncached operation. Add synthetic echo/control/event resources alongside ordinary files. Ship a working skeleton passthrough client and server (the pair the cookbook's examples run against) with a fun example server that serves every file reversed. Provide the server as a reusable library, with a cookbook documenting how to adapt it into a backend to anything.

Gate: mount/read/write/create/link/rename/unlink, cross-user denial, symlink escape resistance, special-file policy, explicit durability, and cancellation work under concurrency. Publish the actual supported OS/client combinations and installation recipes.

### Phase D: round-trip and backend features

Implement COMPOUND, readdir attributes, xattrs, ACL_POSIX, locking, sparse-file operations, and copy. Validate partial outcomes and backend limitations. Benchmark against equivalent `.L` and native 9Pfrank workloads with encryption held constant.

Gate: compounds improve intended workloads without unbounded buffering; lock adapters pass fork/close/dup tests; append and rename guarantees survive contention.

### Phase E: retained sessions and recovery

Implement replay reservations, acknowledgment floors, fencing, retention quotas, and reconnect. Inject disconnects before admission, during backend work, after side effect, before reply, and during resume. Include consuming synthetic reads and writes. Kill the server and verify clients report uncertainty instead of inventing exactly-once behavior.

Gate: no duplicated operation in a successfully retained session, no replay of acknowledged/expired mutations, no cross-principal resume, and no old-epoch operation admitted after fencing.

### Phase F: optional coherency

Specify and model read leases before implementation. Verify interactions with local backend writers, notification overflow, suspend, time drift, session expiry, and authorization changes.

Gate: either demonstrate the cache benefit with correctness evidence, or keep the module optional and disabled. A useful 9Pfrank release does not depend on writable leases, distributed transactions, or transparent failover.

### Phase G: interoperability and release

Run two independent client/server combinations, legacy regression suites, property/fuzz tests, and network/crash fault injection. Publish packet diagrams, a dissector, threat model, compatibility matrix, benchmark scripts/results, and administrator documentation. Ship the spec; a cookbook of fun, worked examples on Linux, OpenBSD, and Windows; the linkable library; complete FFI shims (one `bindings/` subdirectory per language, a binding matrix, and an FFI docs page with the API reference table, C quick start, architecture diagram, and build instructions); the server, client, and a FUSE mount driver for the client; and full documentation (manpages, GNU info, markdown, `README.distributions` with `dist/` packaging templates, an `UNBOXING` quick start, and a `CHANGES` log) in a full GNU autotools layout following GNU standards. Obtain opcode/feature/ALPN/service registration where applicable. Freeze revision 1 only after review of recovery and authorization by people outside the implementation team.

### Cookbook: worked example projects

The cookbook ships these twelve projects in ascending difficulty, each small enough for a junior coder and each adding one new idea on top of the last:

1. **Hello, 9Pfrank**: mount one synthetic `/hello` file that reads a fixed string.
2. **The Clock**: `/time` and `/uptime`, computed on every read; nothing is stored.
3. **Backwards File System**: a passthrough that serves a directory with every file's bytes reversed.
4. **Fortune Cookie**: `/fortune` returns a random line from a quote file on each open.
5. **System Dashboard**: a `/proc`-style mount exposing memory, load, and CPU as synthetic files.
6. **TODO Directory**: one file per todo item; create/remove/write to manage the list.
7. **Guestbook**: write a file to post a timestamped message; read `/log` to view them.
8. **Remote Clipboard**: `/clipboard` as a read/write file mirroring the host clipboard.
9. **Magic Calculator**: write an expression to `/calc` and read the answer, or a `/primes/<n>` tree.
10. **SQLite/API as a Filesystem**: a database table or a REST endpoint served as a directory of files.
11. **FUSE Read-only Mount**: point the existing filsys FUSE adapter at a 9Pfrank client instead of a disk image, exposing the namespace read-only. Interrupt-to-CANCEL mapping and lock owners stay in the full driver. macOS goes through macFUSE; FSKit is not FUSE-compatible.
12. **The Time Capsule**: the grand finale, a server whose files live in any pre-FFS Unix image (V0 through V7, 32V, Coherent, Xenix, 2.9/2.11BSD), read through the filsys library.

These twelve projects are the `examples/` directory; each ships in C against the library and in idiomatic newLISP through the newLISP FFI binding. Because newLISP is single-threaded, the library must expose a caller-owned, poll-driven (non-blocking, no internal threads) event-loop mode so the binding delivers callbacks on the interpreter thread. The cookbook links filsys; record its license alongside 9Pfrank's ISC.

## 11. Decisions deliberately left for review

The initial choices are TLS/TCP, new framing after the legacy bootstrap, portable native flags, typed metadata, bounded compounds, and honest retained-session recovery. The following are explicit release blockers or future design work:

1. Identify and pin the `.e` implementations being covered, and define whether a LING adapter is in the first release or a separately delivered service.
2. Decide the exact full-filesystem conformance matrix when a backend lacks devices, xattrs, ACLs, allocation, copy, or directory fsync. Protocol recognition and backend support must be separately reported.
3. Complete native errno/flag translation tables and ACL fixtures. Review special Plan 9 mode semantics against actual applications.
4. Finalize registered names/numbers, malformed-frame behavior, resource-limit ceilings, and the IDL. The concrete layouts above are reviewable proposals, not allocated standard values.
5. Prove lease expiry and recall rules before enabling coherent caching. Durable replay across restart, distributed locks/failover, snapshots, write delegations, transactions, arbitrary ioctl forwarding, and remote socket operations are outside revision 1.
6. Choose supported mount implementations and deployment platforms after the prototype; do not publish fictional native-kernel support or unmeasured encryption overhead.
7. Decide whether a version string that participates in version(5)'s digit-suffix negotiation (for example `9P2000.F`) is worth same-connection fallback to 9P2000; it is rejected for now to keep the dialect name `9Pfrank`.
8. Pin the exact original-9P wire format (message framing, `Tnop`/`Tsession` session-open types, fixed names and stat records, p9sk1/DES).

The intended result is a small usable core with explicit extension contracts: traditional 9P namespace flexibility, the practical filesystem coverage of its Unix/Linux descendants, fewer round trips, and security that can be deployed and measured on ordinary machines.

## 12. Platform support appendix

The server is userspace and needs no kernel driver, so it runs on Windows and macOS as well as the POSIX family. WinFsp, macFUSE, and FSKit are client mount layers, not server backends. This matrix covers the POSIX backends: Linux, illumos, and the BSDs (FreeBSD, NetBSD, OpenBSD, DragonFly BSD); Windows and macOS backend rows are not yet enumerated.

### 12.1 Conformance vs. backend coverage

A platform's support is determined by which of the protocol's operations its backend can implement (§5.2, §4.3). A platform lacking xattrs or POSIX.1e ACLs is a reduced-profile platform, not an unsupported one: it advertises a smaller profile and reports backend limitations explicitly (§1). The "full filesystem" profile (features 1..7, 9..13, §4.2) is fully realizable only where xattrs, POSIX.1e ACLs, SEEK_HOLE, and fcntl byte-range locks coexist: Linux, and FreeBSD with the ZFS/ACL caveats below. Everywhere else the server advertises a reduced profile.

### 12.2 Backend semantics matrix

Values: **full** (native, matches §5.2), **partial** (different API or filesystem-dependent), **absent**, **verify**.

| Operation (§) | Linux | illumos | FreeBSD | NetBSD | OpenBSD | DragonFly |
| --- | --- | --- | --- | --- | --- | --- |
| xattrs (§5.2) | full | partial¹ | partial | partial | absent | partial |
| POSIX.1e ACLs (§5.2) | full | absent² | full | full | absent | partial |
| SEEK_HOLE / SEEK_DATA (§5.2) | full | full | partial³ | absent | absent | verify |
| fcntl byte-range locks (§5.2) | full | full | full | full | full | full |
| OFD locks (owner model) | full | absent | partial⁴ | verify | absent | verify |
| flock | full | full | full | full | full | full |
| socket peer credentials (§9.1) | full⁵ | partial⁶ | full⁷ | full⁷ | full⁷ | full⁷ |
| statfs / statvfs (§5.1) | full | full | full | full | full | full |
| device/FIFO/socket nodes (§4.3) | full | full | full | full | partial | full |
| FUSE mount client (§9.2) | full | partial⁸ | full | partial⁹ | partial | partial |

1. illumos extended attributes use `openat(O_XATTR)` / `attropen`; a `getxattr` compatibility shim exists. Different API, not a drop-in.
2. illumos uses NFSv4-style ACLs (`acl(2)`), not POSIX.1e; the ACL_POSIX feature must report absent and advertise a reduced profile.
3. FreeBSD supports SEEK_HOLE/SEEK_DATA on ZFS only; UFS returns EINVAL.
4. OFD locks landed in FreeBSD 13; confirm exact version and behavior before relying on it.
5. Linux: `SO_PEERCRED` on Unix sockets.
6. illumos: `getpeerucred(3C)`.
7. the BSDs: `getpeereid(3)`.
8. illumos has no base FUSE; a third-party port exists (verify).
9. NetBSD: perfused / librefuse.

The peer-credential row is a code-level portability issue, not merely a semantic one: §9.1's "Unix socket with peer credentials" needs a backend interface exposing `SO_PEERCRED` (Linux) / `getpeerucred(3C)` (illumos) / `getpeereid(3)` (the BSDs) behind one call. The same applies to the xattr APIs (`getxattr`, `extattr`, `attropen`/`openat(O_XATTR)`): each variant lives in a per-platform `.c` file selected by configure, never behind `#ifdef` in shared code.

### 12.3 Platform notes

- **Linux**: every feature ID in the full-filesystem profile is native; FUSE via libfuse3; peer creds via `SO_PEERCRED`.
- **illumos**: home of SEEK_HOLE/SEEK_DATA and ZFS, but the xattr and ACL models differ (`attropen` / `openat(O_XATTR)`, NFSv4 ACLs) and POSIX.1e ACLs are absent. Reduced profile.
- **FreeBSD**: `extattr` (user/system namespaces) replaces Linux's `getxattr`; POSIX.1e ACLs on UFS and NFSv4 on ZFS; SEEK_HOLE only on ZFS. `fusefs-libs3` for the mount client.
- **NetBSD**: extended attributes and POSIX.1e ACLs present; no SEEK_HOLE/DATA; perfuse/librefuse for FUSE.
- **OpenBSD**: no xattrs, no POSIX.1e ACLs, no SEEK_HOLE; a reduced core profile only.
- **DragonFly BSD**: HAMMER2 coverage of ACLs and SEEK_HOLE unverified.

### 12.4 Verification and fixtures

A cell moves from "verify" or "partial" to a published support claim only when it has a fixture and an OS-specific install recipe, mirroring the Phase C gate ("publish the actual supported OS/client combinations and installation recipes"). The §10 Phase G compatibility matrix gains a platform dimension. Until then, treat every non-Linux cell as a proposal to be proven, not a statement of existing support.
