# Gatekeeper Architecture

## 1. Purpose

This document defines the proposed architecture for Gatekeeper, a local-first CLI
that stores project environment profiles as age-encrypted files and injects
them into child processes.

The architecture optimizes for a solo-maintained application:

- one executable;
- no required daemon or hosted backend;
- a small number of deep modules;
- explicit plaintext exposure;
- testable filesystem and process seams;
- room to add synchronization and MCP without coupling them to encryption.

The primary development and usage platform is Windows, with Linux and macOS
supported. Platform behavior that changes the design is stated explicitly rather
than discovered during implementation.

"Version one" throughout this document means the six-command release defined in
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) §5.1: `gk init`, `gk set`,
`gk list`, `gk run`, `gk import`, and `gk export`. Everything else this document
describes — recipient management, synchronization adapters, MCP — is architecture
that version one does not build. Where a section says something is deferred, the
plan is the authority on what is in and out.

This is a design specification, not a claim that the implementation has been
security audited.

## 2. Context

```text
                         optional sync transport
                    ┌─────────────────────────────┐
                    │ Git / Syncthing / USB       │
                    └──────────────┬──────────────┘
                                   │ ciphertext only
                                   ▼
┌───────────┐ commands   ┌───────────────────┐   encrypted files
│ Developer │───────────▶│ Gatekeeper CLI    │◀──────────────────▶ filesystem
└───────────┘             │                   │
                          │ vault             │   private identity
                          │ runner            │◀──────────────────▶ local config
                          │ recipients (later)│
                          └─────────┬─────────┘
                                    │ environment variables
                                    ▼
                              child process
```

The vault contains ciphertext and non-secret metadata. Private identities remain
outside the vault directory entirely, so moving that directory never moves a key.

Recipient management appears in the diagram because it belongs to the module
architecture, but it is deferred out of version one (§3.7). Version one uses a
single identity shared by all of the user's machines, so the recipient set is
written once by `gk init` and never changes.

## 3. Architectural decisions

### 3.1 Go and a single executable

Go supports cross-compilation, quick startup, filesystem/process primitives,
and the official age and MCP ecosystems. The delivered application should be a
single executable wherever practical.

Windows, Linux, and macOS are all targets, and cross-compiling to any of them
from either development platform is expected to work without a per-target
toolchain. That is the main reason Go was chosen over a language needing a
runtime installed on every machine.

### 3.2 Direct age integration

Gatekeeper uses `filippo.io/age` rather than implementing cryptographic
primitives. Profile recipients are age X25519 recipients. An offline recovery
identity is an additional recipient on every profile.

age is also used for the one secret that is not protected by a key pair: the
identity file on disk is encrypted to a passphrase (§3.8), using age's own scrypt
recipient rather than a bespoke construction.

SOPS remains a useful interoperability reference but is not a runtime
dependency in the first version. Importing from or adding a SOPS adapter should
be considered only after the native format is stable.

### 3.3 One encrypted file per profile

Each environment profile is encrypted independently. Compared with a single
vault blob, this:

- reduces unrelated rewrites;
- narrows a synchronization conflict to one profile;
- permits incremental backup and recovery;
- allows corrupt profiles to be isolated.

It also exposes profile names through filenames. Version one accepts that
metadata leak and documents it.

### 3.4 No database

The expected data volume is tiny. Versioned JSON encrypted as a complete age
payload is easier to inspect, back up, migrate, and test than an encrypted
database. Database-like abstractions are intentionally excluded.

### 3.5 Synchronization is transport-agnostic

The vault is a directory and nothing more. It does not require Git, and Git is
not the assumed transport.

Git works, because it carries ciphertext without inspecting it. So does any
file-synchronization tool, a network share, or removable media. A tool that keeps
no permanent history is preferable when a permanent record of every superseded
ciphertext is unwanted, because deleting a profile then deletes it instead of
leaving it recoverable in a repository forever.

`NoSync` therefore covers all of these cases completely: when something outside
Gatekeeper moves the directory, there is no adapter to write. `GitSync` exists
only as an optional convenience and is never required. Core vault operations
never commit, pull, or push implicitly.

### 3.6 MCP is deferred

MCP must call the same application module as the CLI rather than reading vault
files directly. It is not part of the first release. A generic secret-reading
tool is explicitly excluded.

### 3.7 One identity for all machines in version one

Version one issues a single identity, shared by every machine the user owns, in
addition to the offline recovery identity. This is a policy choice rather than a
property of the format: profiles are encrypted to a list of recipients, so
issuing one identity per machine later is additive and needs no format change.

The consequence is that per-machine revocation is unavailable, and one
compromised machine compromises the identity. Adding and removing recipients is
therefore deferred out of version one (§6.4). Deferring it also removes the
multi-file re-encryption transaction and the crash-injection requirement that
guarded it.

### 3.8 The identity file is passphrase-encrypted

The private identity is written to disk as an age payload encrypted to a
passphrase, using age's scrypt recipient. Unlocking it yields the X25519
identity. The passphrase is requested once per session and the unlocked identity
is held in memory for that session, in the manner of `ssh-agent`, rather than
being requested on every command.

Profiles themselves remain encrypted to a random X25519 recipient, never to the
passphrase. The distinction is deliberate and load-bearing:

- a random X25519 key cannot be attacked offline at all, so profile ciphertext
  stays unbreakable no matter who obtains the vault directory;
- a passphrase-encrypted payload *can* be attacked offline by anyone who obtains
  it, so confining the passphrase to one small file keeps that exposure as narrow
  as possible.

Encrypting the profiles directly with a passphrase is therefore explicitly
rejected. It would make every profile in the vault directory offline-crackable,
which is a downgrade rather than a protection.

This replaces the need for full-disk encryption. Without disk encryption a raw
key file is readable by anyone who obtains the machine; a passphrase-encrypted
identity file is not. It also protects the identity if the file itself leaks,
because the passphrase is not stored alongside it.

### 3.9 Multiple vaults

A user may keep more than one vault, for example a personal vault and a work
vault. Vaults are fully independent and never share a key.

A command selects its vault from, in order: the `--vault` flag, the `GK_VAULT`
environment variable, then the machine-local default recorded when the vault was
initialized. Local identities are keyed by vault identifier, so two vaults cannot
collide.

### 3.10 Windows is the primary platform

Windows is where this tool is primarily developed and used, and several
assumptions a POSIX-first design would make do not hold there. The differences
change the implementation rather than the configuration, so they are stated here
instead of being handled as special cases scattered through shared code.

**File permissions are not the access-control model.** `os.Chmod` on Windows only
toggles the read-only attribute; it does not restrict which users can read a
file. An identity that reports `0600` can still be readable by every local user.
Enforcing owner-only access means writing a DACL and removing inherited entries,
which the Go standard library does not expose. The fallback is to require the
identity to live under the per-user profile directory, which Windows already
restricts to the owning user, and to refuse to load one found anywhere else.

**Rename is not atomic by default.** `os.Rename` maps to `MoveFileEx` with
`MOVEFILE_REPLACE_EXISTING`, which fails with a sharing violation whenever another
process holds the destination open. On a working desktop that is routine rather
than exceptional: the antimalware scanner, the search indexer, and any
file-synchronization client all touch files without warning. A bounded retry with
backoff is the minimum acceptable behavior. `ReplaceFile`, or
`SetFileInformationByHandle` with `FILE_RENAME_INFO`, is the correct fix and
should replace the retry once the persistence path is stable.

**Locking differs, and the Windows primitive is better.** `flock` is Unix-only.
Opening a lock file with exclusive share mode gives a mandatory lock that the
operating system releases when the process dies, so there are no stale locks and
no staleness heuristic to get wrong. That behavior is preferable on every
platform, so it is the intended implementation rather than a Windows branch.

**Executables are frequently shell shims.** On Windows, `npm`, `yarn`, `tsc` and
many other familiar commands resolve to `.cmd` or `.bat` scripts, which
`CreateProcess` cannot launch directly.

The two things invariant 6 protects are not the same thing, and separating them
resolves this. What matters is that `run` never *re-interprets arguments as shell
syntax*: arguments are passed as a list and never joined into a command line. That
holds in every case. Whether a batch file is started through `cmd.exe` is a
platform fact rather than a policy choice — a `.cmd` file is a shell script, and
there is no other way to run it. Refusing would impose a daily papercut on the
primary platform for no security gain, since typing `npm run dev` in a prompt
imposes exactly the same quoting rules.

So: a batch shim is started through `cmd.exe`, and Gatekeeper says so on standard
error. It is never silent. Everything else, on every platform, is started
directly.

## 4. Files and data formats

### 4.1 Vault directory

```text
.gatekeeper/
├── manifest.json
├── devices.json
├── .gitignore
└── profiles/
    ├── website-dev.age
    └── website-production.age
```

The directory is named `.gatekeeper/` by convention when it sits inside a
project. It may live anywhere, and is normally placed where a synchronization
tool already operates (§3.5).

`manifest.json` is plaintext metadata:

```json
{
  "format": 1,
  "vault_id": "0195f03a-...",
  "name": "personal",
  "created_at": "2026-09-16T18:00:00Z"
}
```

`devices.json` contains public information only:

```json
{
  "format": 1,
  "revision": 1,
  "devices": [
    {
      "id": "0195f04b-...",
      "name": "personal",
      "recipient": "age1...",
      "added_at": "2026-09-16T18:05:00Z"
    }
  ],
  "recovery_recipient": "age1..."
}
```

Each entry is a recipient: a public key that may decrypt. The file is named for
its shape rather than its contents, and "device" and "recipient" mean the same
thing in this document.

Public recipients are not secrets. The device file must still be validated
strictly because tampering could add an attacker's recipient. Changes to the
recipient set require decrypting with an existing identity and explicit user
confirmation before profiles are re-encrypted.

Version one writes this file once at initialization and never changes it, because
adding and removing recipients is deferred (§3.7).

### 4.2 Local, unsynchronized data

Local state lives outside any vault, under a platform-appropriate directory:

```text
~/.config/gatekeeper/                # Linux and macOS
%LOCALAPPDATA%\gatekeeper\           # Windows
├── identities/<vault-id>.key
└── config.json
```

`identities/<vault-id>.key` holds the private identity, encrypted to a passphrase
(§3.8). It is never written in raw form, never placed in a vault, and never
synchronized. `config.json` holds non-secret machine-local settings, currently
the default vault path (§3.9).

LocalAppData is used on Windows rather than the Roaming AppData that Go's
`os.UserConfigDir` returns. A roaming profile is copied to and from a domain
controller at logon, and a private key should not travel that way.

Access is enforced as strictly as each platform allows. On POSIX systems the
identity is created `0600` and its directory `0700`, and an identity with looser
modes is refused rather than used. On Windows those modes carry no access-control
meaning (§3.10), so the identity must live under the per-user profile directory
and is refused if it is found anywhere else.

A vault must ignore all identity files, plaintext exports, temporary files, and
editor swap files, so that a careless `git add -A` — or the equivalent in another
synchronization tool — cannot capture them. This is a backstop rather than the
primary control, because the identity does not live in the vault to begin with.

### 4.3 Encrypted profile payload

After decryption, a profile contains:

```json
{
  "format": 1,
  "id": "0195f061-...",
  "name": "website-dev",
  "revision": 8,
  "updated_at": "2026-09-16T18:30:00Z",
  "variables": {
    "DATABASE_URL": "postgres://...",
    "OPENAI_API_KEY": "sk-..."
  }
}
```

Rules:

- Variable names must match a documented portable subset such as
  `[A-Za-z_][A-Za-z0-9_]*`.
- Values are arbitrary UTF-8 strings in version one; NUL bytes are rejected
  because process environments cannot represent them portably.
- Unknown format versions fail closed.
- Duplicate JSON keys are rejected during decoding.
- Profile filename and decrypted profile name must agree.
- A revision increments on every successful mutation.

### 4.4 Atomic persistence

Profile updates follow this sequence:

1. Decrypt and validate the current profile.
2. Apply the mutation in memory.
3. Encrypt to a temporary file in the same directory.
4. Flush and close the temporary file.
5. Set restrictive permissions.
6. Atomically replace the destination, retrying briefly on the transient sharing
   violations Windows raises while another process holds the file open (§3.10).
7. Best-effort sync the parent directory where supported.

Temporary paths must be unpredictable, must not contain plaintext, and must be
removed after failures. The original ciphertext remains intact unless the new
encrypted file is complete.

## 5. Module map

```text
cmd/gk
    │
    ▼
application  ───────────────▶ sync
    │                           ▲
    ├──────────────▶ runner     │ adapter seam
    │
    ▼
vault
    │
    ├──────────────▶ cryptography
    ├──────────────▶ filesystem
    └──────────────▶ identity
```

Each module owns meaningful behavior behind a small interface. Command handlers
parse input and render results; they do not contain vault, encryption, or Git
logic.

### 5.1 Application module

The application module is the use-case interface shared by CLI and future MCP
entry points. It prevents either entry point from bypassing policy.

The version-one interface. It mirrors the six commands the plan commits to, so the
surface and the plan cannot drift apart:

```go
type App interface {
    Init(ctx context.Context, req InitRequest) (InitResult, error)
    Profiles(ctx context.Context) ([]ProfileSummary, error)
    List(ctx context.Context, profile string) (ProfileSummary, error)
    Set(ctx context.Context, req SetRequest) (ChangeResult, error)
    Environment(ctx context.Context, profile string) (Environment, error)
    Import(ctx context.Context, req ImportRequest) (ChangeResult, error)
    Export(ctx context.Context, req ExportRequest) error
}
```

`Set` creates the profile when it does not exist, because `gk profile create` is
deferred. Creating an *empty* profile arrives with it later.

This interface deliberately describes user operations rather than storage
operations. `Unset` and `Reveal` are deferred alongside `gk unset` and `gk show`,
and recipient management is deferred entirely (§3.7). Import and export are
separate operations here because their request and result shapes differ
substantially from a single-variable change; `Profiles` and `List` are separate
because `gk list` with no argument names profiles and `gk list PROFILE` names
variables.

`SecretValue` and `Environment` types must avoid `String()` implementations or
default structured logging that could reveal their contents.

### 5.2 Vault module

The vault module is the deepest module. It owns profile validation, encrypted
persistence, revisions, recipient selection, atomic writes, and format
migration.

Proposed interface:

```go
type Vault interface {
    List(ctx context.Context) ([]ProfileSummary, error)
    Read(ctx context.Context, name string) (Profile, error)
    Change(ctx context.Context, name string, fn ChangeFunc) (ProfileSummary, error)
}
```

`Change` centralizes read-modify-encrypt-write behavior so callers cannot
accidentally bypass atomic persistence or revision checks. Creation and deletion
can be expressed as explicit methods if forcing them through `Change` makes its
interface harder to understand.

The vault implementation accepts cryptography, filesystem, identity, and clock
dependencies. It does not construct global dependencies internally.

### 5.3 Cryptography module

This module is a narrow adapter around age:

```go
type Envelope interface {
    Encrypt(dst io.Writer, recipients []age.Recipient, writePlaintext func(io.Writer) error) error
    Decrypt(src io.Reader, identities []age.Identity, readPlaintext func(io.Reader) error) error
}
```

The callback shape limits accidental plaintext copies and permits streaming.
The module owns age parsing, recipient validation, passphrase (scrypt) recipient
handling, error normalization, and payload size limits. It must never log
plaintext, identities, passphrases, or secret values.

### 5.4 Identity module

The identity module owns key generation, local identity discovery and unlocking,
access checks, the session cache of the unlocked identity, and recovery identity
output.

Its interface returns parsed age identities and recipients, not raw private-key
strings, except for the one explicit recovery-export operation.

Loading an identity means decrypting it with the passphrase (§3.8), so this module
owns the passphrase prompt and the in-memory cache of the unlocked identity for
the session. It never writes an unlocked identity to disk, never places one in an
environment variable, and never logs one.

Access checking is platform-specific and belongs here rather than in callers
(§3.10).

Removing a recipient, when that is implemented, changes only future encryption
recipients. Its result must include a warning that previous encrypted revisions
remain decryptable by that recipient and that sensitive credentials may require
rotation.

### 5.5 Runner module

The runner combines the current environment with a decrypted profile and starts
a child process:

```go
type Runner interface {
    Run(ctx context.Context, command Command, env Environment) (ExitResult, error)
}
```

Rules:

- Profile values override existing variables only when explicitly documented.
- The runner passes arguments directly to `exec`, never through an implicit
  shell.
- Standard input, output, and error attach to the invoking terminal.
- Signals and exit codes propagate as faithfully as the operating system
  permits.
- Commands and variable names may be logged; variable values may not.
- On Windows, a command resolving to a `.cmd` or `.bat` shim cannot be launched
  directly. The runner refuses with a typed error naming the shim rather than
  routing through a shell implicitly; how this is ultimately resolved remains
  open (§3.10, §12).

### 5.6 Synchronization module

Synchronization is explicit:

```go
type Sync interface {
    Status(ctx context.Context) (SyncStatus, error)
    Pull(ctx context.Context) (SyncResult, error)
    Push(ctx context.Context, message string) (SyncResult, error)
}
```

`NoSync` is the expected default, and it is not a stub: when the vault directory
is moved by an external tool, that external copying *is* the synchronization and
there is nothing for Gatekeeper to do. It covers Git, file-synchronization tools,
network shares, and removable media equally (§3.5).

`GitSync` is an optional adapter that invokes Git with argument arrays rather than
a shell. It refuses to overwrite conflicts, reports actionable state, and leaves
recovery to an explicit workflow. Vault mutations must not automatically push,
because network and repository behavior should not be hidden inside secret
operations.

Because ciphertext cannot be merged, a synchronization conflict is never resolved
automatically, whatever the transport.

### 5.7 Command module

Cobra commands are thin adapters. Each command:

1. parses and validates non-secret arguments;
2. obtains secret input through a no-echo terminal prompt where applicable;
3. invokes one application operation;
4. renders a result to the appropriate output stream;
5. maps typed errors to documented exit codes.

Commands must not call age or inspect encrypted files directly.

## 6. Primary flows

### 6.1 Initialize

```text
user
  │ gk init
  ▼
application
  ├─ verify target directory is safe and empty
  ├─ generate vault ID
  ├─ generate identity
  ├─ generate recovery identity
  ├─ request a passphrase and persist the identity encrypted to it, outside the vault
  ├─ persist public manifest and recipient metadata
  └─ display/save recovery identity exactly once
```

Initialization fails rather than overwriting an existing vault or identity.
Recovery output must not be printed when standard output is redirected unless
the user explicitly supplies an output destination.

The recovery identity is emitted once and never persisted by Gatekeeper. It is the
documented backstop for a forgotten passphrase as well as for a lost machine: if
the session passphrase is forgotten, the recovery identity still decrypts every
profile, because it is an independent key and not a copy of the identity on disk.

### 6.2 Set a value

```text
terminal no-echo prompt
       │
       ▼
application.Set
       │
       ▼
vault.Change
       ├─ decrypt
       ├─ validate revision and profile
       ├─ mutate in memory
       ├─ encrypt to all recipients
       └─ atomic replacement
```

### 6.3 Run a command

```text
application.Environment
       │ decrypt + validate
       ▼
runner.Run
       │ explicit argv + constructed environment
       ▼
child process
```

The CLI never prints the constructed environment. If command startup fails, the
error may include the executable name but not environment values.

### 6.4 Add a device

Deferred out of version one (§3.7). Retained here because the design is settled,
and the deferral is a scheduling decision rather than a change of approach.

1. Parse and confirm the new public recipient and name.
2. Acquire an exclusive vault mutation lock.
3. Decrypt every profile with an existing identity.
4. Re-encrypt every profile to the old recipients plus the new recipient.
5. Update recipient metadata only after all profile replacements succeed.
6. Provide a summary suitable for a separate commit or synchronization step.

This flow requires a transaction strategy across multiple files. It may use a
staging directory and swap only after all files are successfully created. A
crash-injection test is required before recipient management is called stable.
None of this is needed for version one, which never changes the recipient set.

## 7. Concurrency and conflict behavior

Gatekeeper is single-user but may be used on multiple machines.

- Local mutations acquire an exclusive lock in the vault directory.
- The lock is held by opening the lock file with exclusive share mode, so the
  operating system releases it when the process dies. There are no stale locks to
  detect and no staleness heuristic to get wrong (§3.10).
- Profile revisions detect the stale reads a lock cannot: a profile changed on
  another machine and then synchronized in.
- Divergence between copies of the vault is never merged automatically, because
  ciphertext is opaque. This holds for every transport, not only Git.
- Users should synchronize before mutating and again afterward, whatever tool
  performs the synchronization.
- If two machines edit the same profile concurrently, Gatekeeper stops and offers
  an explicit export/compare/reapply workflow rather than choosing a winner.

Per-profile files make unrelated profile edits less likely to conflict, and
`devices.json` is written once at initialization, so it does not change under
concurrent editing (§3.7).

## 8. Threat model

### 8.1 Protected against

- Theft of the vault directory without an authorized identity
- Theft of a machine that is not disk-encrypted, because the identity stored on it
  is encrypted to a passphrase (§3.8)
- Disclosure of the identity file itself, for the same reason
- Accidental commit of plaintext through ordinary Gatekeeper operations
- Partial writes and many crash-corruption scenarios
- Casual disclosure through list and status commands
- Shell interpolation caused by the runner itself, subject to the unresolved
  Windows shim case (§3.10)
- Unintentional logging of values by Gatekeeper

### 8.2 Not protected against

- A compromised operating system or administrator/root account
- Malware running with the user's privileges. This defeats every protection
  described here: it can read the passphrase as it is typed, read the unlocked
  identity or the decrypted values from process memory, or read the child's
  environment. Nothing in this design changes that.
- A weak passphrase. An attacker who obtains the encrypted identity file can
  attack it offline at leisure, so the strength of that passphrase is the only
  thing standing between the file and every secret. This is the price of not
  relying on full-disk encryption.
- Malicious code launched with `gk run`
- A user deliberately revealing or exporting a value
- Loss of every identity and of the recovery identity
- Decryption of historical revisions by a formerly authorized recipient
- Weaknesses or misuse in third-party applications receiving the variables
- Availability failures in the storage or synchronization tool

### 8.3 Important security invariants

1. Private identities never enter the vault directory.
2. Plaintext values never appear in command arguments, logs, error messages, or
   filenames.
3. Persistent profile writes are encrypted before touching their final path.
4. Listing profiles or variable names does not reveal values.
5. Unknown formats and invalid recipient metadata fail closed.
6. `run` never re-interprets arguments as shell syntax. Arguments are handed over
   as a list and never joined into a command line. A shell is used only when the
   named executable is itself a Windows batch file — the only way to run one —
   and that is announced on standard error rather than done silently.
7. Adding recipients always requires an already authorized identity and an
   explicit confirmation.
8. Removing a recipient never claims to revoke historical access.
9. The private identity exists on disk only in passphrase-encrypted form. The
   offline recovery identity is the single exception, and it is emitted once and
   never persisted by Gatekeeper.

### 8.4 Operational mistakes dominate

The realistic way secrets are lost is not cryptanalysis. It is a person making a
mistake: committing an identity file, exporting a plaintext `.env` and forgetting
it exists, or pasting a value into a chat.

Most of the guardrails in this design exist for that reason rather than for
attackers:

- a pre-commit check that refuses to commit an identity file;
- `export` requiring an explicit flag and a warning before it writes plaintext;
- never printing a value except in the one deliberately named operation;
- keeping identities out of the vault, so a broad `git add` or an equivalent
  cannot reach them.

None of these are cryptographic controls, and they should not be judged as such.
They address the failure mode that actually occurs.

## 9. Error model

Core modules return typed errors that commands translate into stable exit codes:

| Category | Example | Suggested exit |
| --- | --- | --- |
| Usage | Invalid profile name, or no vault selected | 2 |
| Not found | Missing profile, variable, or file named on the command line | 3 |
| Locked | No matching local identity, or a passphrase that does not unlock it | 4 |
| Conflict | Revision or synchronization conflict | 5 |
| Integrity | Invalid or corrupted encrypted payload | 6 |
| Permission | Unsafe identity file permissions, or an identity outside the per-user profile on Windows | 7 |
| External | Synchronization or child-process startup failure | 8 |

The classification is by sentinel, not by message, so wrapping an error does not
change its code. "Not found" covers `os.ErrNotExist` as well as the vault and
identity sentinels: a mistyped `--passphrase-file` is a path the user can fix, and
reporting it as an unclassified failure (1) made a typo look like a bug here.

Detailed errors should be useful without including sensitive values. Wrapped
errors are allowed only after reviewing the upstream message for disclosure.

## 10. Testing strategy

The interface of each deep module is its primary test surface.

### Unit tests

- Profile and variable-name validation
- Versioned JSON decoding, including duplicate and unknown fields
- Environment merge rules
- Command argument handling
- Typed error and exit-code mapping
- Recipient-set validation
- Vault selection precedence across the flag, `GK_VAULT`, and the machine-local
  default

### Module tests

- Vault create/read/change through an in-memory or temporary filesystem adapter
- Encryption round trips with generated age identities
- Wrong identity and corrupted ciphertext behavior
- Atomic-write failures injected at each persistence step
- Atomic replacement under a simulated Windows sharing violation, verifying that
  the retry is bounded and eventually gives up rather than spinning (§3.10)
- Lock acquisition, mutual exclusion, and release when the holder dies
- Identity access validation on each platform, including the Windows
  per-user-profile rule (§3.10)
- Passphrase handling: a wrong passphrase is refused, an unlocked identity is
  cached for the session, and no unlocked identity is ever written to disk
- Runner environment injection without shell interpolation
- The Windows shim classifier, which is testable on every platform because it is
  a classification rather than a syscall (§3.10)

### End-to-end tests

- Initialize, set a fake value, list its name, and run a fixture process
- Verify ciphertext and captured logs do not contain the fake value
- Confirm that the identity file on disk yields no usable private key without the
  passphrase, and that the offline recovery identity still decrypts with the
  passphrase forgotten (§3.8)
- Import and explicit export round trip
- Simulated concurrent profile edits stop with a conflict
- Recipient addition and removal are deferred (§3.7) and carry their tests,
  including the crash-injection requirement for the re-encryption transaction,
  with them

Tests use distinctive canary values and scan test artifacts for disclosure.
Real credentials are never used in the test suite.

## 11. Future seams

Future work should be added only after a second adapter or caller makes the seam
real:

- **MCP adapter:** calls the application module; never reads vault files.
- **UI adapter:** local web or desktop UI calling the same application module.
- **SOPS adapter:** optional import/export interoperability.
- **OS keychain adapter:** would hold or unlock the identity so the passphrase is
  never typed. Whether to add it is open (§12).
- **Alternative sync adapters:** expected to remain unnecessary, because external
  tools synchronize the directory without integration (§3.5).

Avoid a plugin system until at least two independently useful extensions exist.

## 12. Open decisions

- How `run` should handle Windows `.cmd` and `.bat` shims, which `CreateProcess`
  cannot launch directly (§3.10)
- How a synchronization conflict is recovered when two machines edited the same
  profile. Ciphertext cannot be merged, so nothing is ever merged automatically
  (§7) — but the export/compare/reapply workflow a user follows is not yet defined
- Whether the Linux machine is WSL on the same host as the Windows machine or a
  separate computer, which decides whether it shares or duplicates the Windows
  identity and how configuration paths resolve
- Whether to add OS keychain integration later, removing the passphrase prompt
  (§11)
- License
- Maximum encrypted profile size

These decisions should be resolved with small prototypes and threat-focused
tests rather than additional abstraction.
