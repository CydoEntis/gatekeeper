# Gatekeeper Implementation Plan

**This is the authoritative plan.** It supersedes earlier drafts and folds in
every decision settled during design. If this document and another disagree, this
one wins — except for the security invariants in
[`ARCHITECTURE.md`](ARCHITECTURE.md), which are requirements rather than plans.

Last updated: 2026-09-17

---

## 1. What we are building

A local-first command-line vault for project environment variables.

The problem, in the user's words: secrets and API keys exist on one machine and
cannot be brought to another, because the obvious mechanism — putting them in a
Git repository — would expose them.

The answer: **profiles of `KEY=value` pairs are encrypted to files with `age`,
the encrypted directory is copied between machines by whatever transport is
convenient, and `gk run PROFILE -- command` injects a profile into a child process
so no plaintext `.env` is ever written.** Only ciphertext moves between machines;
the one thing carried by hand is a single key file, once per machine.

This is a **personal tool, not a product.** It is not intended to be viral, to
make money, or to serve anyone else. The bar it has to clear is narrow and
specific: *solve this one annoyance without creating a new security problem.*
It is a convenience layer over solved cryptography, not new security
infrastructure, and it should never grow into more than that.

---

## 2. Settled decisions

Do not relitigate these without recording why. Each was decided deliberately.

| Decision | Value |
| --- | --- |
| Name | **Gatekeeper** |
| Binary and command | **`gk`** |
| Language | **Go** — one static binary across four heterogeneous machines |
| Command framework | Cobra |
| Encryption | `filippo.io/age`, X25519. **No custom cipher, nonce, KDF, or MAC code, ever.** |
| Storage | One encrypted, versioned JSON file per profile |
| Sync | **Transport-agnostic.** The vault is a directory; Git, a file-sync tool, or removable media all work. No sync code in v0.1. |
| Identity on disk | **Passphrase-encrypted** with age's scrypt recipient |
| Recovery identity | **Raw key, stored offline**, never on disk |
| Devices | **One identity shared by all machines** in v0.1 |
| Vaults | Multiple supported (personal, work) via `--vault`, `$GK_VAULT`, then a configured default |
| Local config | `~/.config/gatekeeper/` on Linux and macOS; `%LOCALAPPDATA%\gatekeeper\` on Windows |
| Execution | Direct `os/exec`. Arguments are never re-parsed as shell syntax. Windows batch shims are started through `cmd.exe` and announced on stderr — never silently. |
| Testing | Go standard library, temporary directories, fake values only |
| Database | None. No server, no daemon, no account. |

---

## 3. Security model

### 3.1 How a secret is protected

Each identity is a key pair:

- the **public** half (`age1...`) encrypts;
- the **private** half (`AGE-SECRET-KEY-1...`) decrypts.

The relationship is one-way. `init` generates two pairs: a device pair and a
separate offline recovery pair. Every profile is encrypted to **both** public
halves, so losing every machine is survivable.

What therefore lives in the synchronized directory:

| Item | Safe to copy anywhere? |
| --- | --- |
| Encrypted profiles | Yes — opaque ciphertext |
| `manifest.json` | Yes — a vault id, a name, a date |
| `devices.json` | Yes — **public** keys only |
| The private identity | **No — and it is never there** |

Verified against the reference `age` implementation: a stolen copy of the vault
decrypts to nothing without the private key, and a public recipient cannot be used
as an identity at all.

### 3.2 The passphrase, and the alternative we deliberately rejected

The private identity file on disk is **encrypted with a passphrase** using age's
scrypt recipient.

The rejected alternative matters, because it is the obvious wrong turn:
encrypting the *profiles* with a passphrase would make the ciphertext in the
synced directory **offline-crackable**. Keeping profiles encrypted to a random
256-bit key — and putting the passphrase only on the small key file — preserves
uncrackable ciphertext and adds the passphrase on top.

**Consequence: full-disk encryption is not required.** The passphrase is what
protects a stolen powered-off machine.

Two honest properties:

- **The passphrase is now the single thing standing between a stolen laptop and
  everything.** Minimum 12 characters, confirmation required, and a warning below
  20. Five or six random words is the recommendation. Not a variant of a password
  already in use elsewhere.
- **Forgetting it is recoverable.** The offline recovery identity is a separate
  key, so a forgotten passphrase means digging out the recovery key, not losing
  the vault. That backstop is the only reason this is safe to adopt.

**v0.1 prompts every time — there is no persistent cache.** This is deliberate.
Caching the unlocked key to disk would restore the exact exposure the passphrase
removes, for the duration of the cache. A handful of prompts a day is the price of
the protection being real. An opt-in session cache (ssh-agent style) is a possible
later addition with that trade-off documented.

### 3.3 What is protected, and what is not

| Threat | Outcome |
| --- | --- |
| A copy of the synced directory leaks | **Safe** — ciphertext only |
| A powered-off machine is stolen | **Safe** — key file is passphrase-encrypted |
| The key file itself leaks | **Safe** if the passphrase is strong; offline attack is the exposure |
| A weak passphrase is used | **Total loss** — the one failure mode to avoid |
| Malware running as the user | **Compromised.** It can read the passphrase as typed or the plaintext from memory. No design here fixes this. |
| Deliberate `export` to a `.env` | Outside the model; the file's lifecycle is the user's |
| Operational mistakes | **The dominant real-world risk.** See below. |

**Cryptography is not the weak link; operational mistakes are.** Committing an
identity file, exporting a plaintext `.env` and forgetting it, or pasting a value
into a chat are how secrets actually get lost. The guardrails in step 6 exist for
this reason, and they matter more than any additional crypto.

### 3.4 Security invariants

Requirements, not aspirations. Each needs an automated test.

1. Private identities never enter the vault directory.
2. Plaintext values never appear in arguments, logs, error output, or filenames.
3. Persistent writes are encrypted before touching their final path.
4. Listing profiles or variable names never reveals values.
5. Unknown formats and invalid recipient metadata fail closed.
6. `run` never invokes a shell unless the user explicitly names a shell as the
   executable. *(Contested on Windows — see §7.)*
7. Adding a recipient requires an already-authorized identity and explicit
   confirmation.
8. Removing access never claims to revoke what was already decryptable.

---

## 4. Layout and formats

### 4.1 The vault directory

```text
<vault>/
├── manifest.json          # plaintext metadata
├── devices.json           # public recipients only
└── profiles/
    └── website-dev.age    # one encrypted file per profile
```

Private identities live outside this directory, always.

### 4.2 Local machine state

```text
<config>/gatekeeper/
├── config.json                              # non-secret; default vault path
└── identities/<vault-id>.key                # passphrase-encrypted private identity
```

An identity is keyed by vault id, so a personal vault and a work vault coexist
without sharing a key.

### 4.3 The decrypted profile payload

```json
{
  "format": 1,
  "id": "0195f061-...",
  "name": "website-dev",
  "revision": 8,
  "updated_at": "2026-09-17T18:30:00Z",
  "variables": { "DATABASE_URL": "postgres://...", "OPENAI_API_KEY": "sk-..." }
}
```

Rules: variable names match `[A-Za-z_][A-Za-z0-9_]*`; values are arbitrary UTF-8
with NUL rejected; unknown format versions fail closed; duplicate JSON keys are
rejected; the decrypted name must match the filename; the revision increments on
every mutation.

Note that `encoding/json` gives none of duplicate-key detection, trailing-content
rejection, or unknown-field rejection for free. `DisallowUnknownFields` covers
one; the others are hand-written. This was found by a test, not by review.

### 4.4 Atomic persistence

Decrypt and validate → mutate in memory → encrypt to a temp file **in the same
directory** → flush → close → restrictive permissions → atomic replace → sync the
directory. The temp file never contains plaintext, and the original ciphertext
survives unless the replacement completes.

---

## 5. Command surface

### 5.1 v0.1 — six commands

| Command | Purpose |
| --- | --- |
| `gk init` | Create a vault, a device identity, a recovery identity, and set the passphrase |
| `gk use DIR` | Point this machine at an existing vault, so no command needs `--vault` |
| `gk set PROFILE KEY` | Prompt without echo and store one value; **creates the profile if it does not exist** |
| `gk list [PROFILE]` | With no argument, name the profiles; with a profile, name its variables. Never values |
| `gk run PROFILE -- CMD` | Run a child process with the profile injected |
| `gk import PROFILE FILE` | Import a dotenv file |
| `gk export PROFILE --output FILE` | Write a plaintext dotenv file, explicitly |
| `gk doctor` | Check the vault, identity and permissions — and refuse to commit secrets with `--pre-commit` |
| `gk sync` | Pull, commit, push — three ordinary git commands, and the only thing here that touches the network |
| `gk flag PROFILE KEY` | Mark a key as exposed until its value is replaced |
| `gk unflag PROFILE KEY` | Clear that mark without changing the value |
| `gk passwd` | Re-encrypt the identity under a new passphrase |

**`--identity PATH`** is a global flag that opens a vault with a raw age private
key instead of the local identity. That is the recovery path — how the offline
recovery key is actually used — and it is why recovery is a command rather than a
paragraph of documentation.

`import` and `export` are pulled forward from the original plan's Phase 7 on
purpose. `import` is how the vault gets populated at all — nobody types forty keys
by hand — and `export` is how it cooperates with tools that expect a `.env`. A
vault that cannot easily be filled is not a vault.

### 5.2 Later

`profile create`, `profile list`, `unset`, `show`, `passwd`, `device list`,
`device add`, `device remove`, `doctor`, `sync`. Each is defensible; none is
needed to stop re-entering keys.

`gk passwd` (change the passphrase) is trivial — re-encrypt the key file — and
should be added as soon as the passphrase exists, but it does not block anything.

---

## 6. Build plan

Each step leaves the repository building, formatted, vetted, and tested. Prefer
one reviewable behaviour and its tests per commit.

### Step 1 — `init` and identity storage ✅ **done**

Vault creation, device identity, recovery identity, permissions, atomic metadata
writes, and rollback so a failed init leaves neither a vault without a key nor a
key without a vault.

*Acceptance:* identity provably outside the vault; re-init refuses; redirected
stdout cannot capture the recovery identity; failure leaves nothing behind.
All covered by tests.

### Step 2 — passphrase-protected identity ✅ **done**

- The identity file is encrypted at rest with age's scrypt recipient, and ASCII
  armored.
- `init` prompts for a passphrase with confirmation; under 12 characters is
  refused, under 20 warns.
- Loading prompts once per invocation and holds the identity in memory only.
- Non-interactive use requires `--passphrase-file`, which must be `0600`.
  **Never an environment variable or an argument** — both leak the passphrase to
  every child process `gk run` starts, and to the process list.
- Refuses to prompt when there is no terminal and no explicit source.

*Acceptance:* verified. The identity file on disk contains no key material and is
readable by the stock `age` library with the passphrase and by nothing else; a
wrong passphrase fails cleanly; a CRLF-converted copy still opens; the recovery
identity still decrypts profiles produced by the device identity.

Two implementation notes worth keeping:

- This reused the existing `Envelope` path entirely. `ScryptRecipient` and
  `ScryptIdentity` already satisfied the interfaces, so **no new cryptography was
  written** — the whole change is one small file plus the identity loader.
- Armor is not cosmetic. A raw binary identity file is silently corrupted by
  anything that rewrites line endings, and the failure looks like a wrong
  passphrase. Armor makes that impossible.

### Step 3 — `set` and `list` ✅ **done**

- `set` reads the value through a no-echo terminal prompt, or from a `0600` file
  named with `--value-file`. **Never from an argument** — an argument is visible
  in shell history and in the process list, which is the exact thing this tool
  exists to prevent.
- **`set` creates the profile on first use.** With `gk profile create` deferred,
  this is what makes a profile exist at all — an upsert, not an error. Creating an
  *empty* profile is the convenience that arrives with `profile create` later.
- `list` shows names, counts and revisions, never values. **With no argument it
  names the profiles.** That is not decoration: with `gk profile list` deferred,
  `gk list` with no argument is the only way to discover what exists.
- Name checks are pure string work and happen *before* the vault is unlocked, so a
  typo costs the user no typing.
- Both delegate to the application module; the handlers stay thin.

*Acceptance:* verified. `set` echoes nothing and writes no plaintext; `list`
cannot leak because the type it prints has no value field; a non-terminal value
source is refused; a world-readable `--value-file` is refused; rejected names are
caught before any unlock; a wrong passphrase exits as *locked*, not *corrupt*.

One bug the end-to-end run caught that no unit test had: profiles were being
written to the vault root instead of `profiles/`, so `gk init` created a
`profiles/` directory that nothing ever wrote to, and the implementation silently
disagreed with §4.1. Fixed. Running the thing for real is not optional.

### Step 4 — `import` and `export` ✅ **done**

**Built before `run`, reversing the original order.** Two reasons. It is the bulk
entry path, so it removes the real friction of entering many secrets — one command
and one passphrase instead of twenty of each — and it was not blocked, while `run`
was waiting on the Windows `.cmd` decision.

- A small, documented dotenv parser. **Parsing is data handling and never
  evaluation**: no `$VAR` expansion, no command substitution, no shell.
- `import` creates the profile, is idempotent for unchanged values, refuses a
  collision *before* writing anything, and replaces only with `--overwrite`.
- `export` writes `0600`, warns loudly on standard error, refuses to overwrite
  without `--force`, and refuses standard output without an explicit `--stdout`.

*Acceptance:* verified. A file containing `$(touch marker)` and backticks neither
executes nor alters anything, and the literal text is what gets stored; a refused
import leaves the profile byte-identical; export then import is lossless across
whitespace, quotes, empty values, Unicode, embedded `#`, and a multiline PEM.

Two deliberate asymmetries worth keeping:

- **A dotenv being imported gets a permission *warning*, not a refusal.** The
  passphrase and single-value files are things Gatekeeper asks you to create, so
  refusing a loose one is right. A `.env` you already had is different, and
  refusing it would block the main way anyone adopts this tool.
- **`$` is escaped on export** even though this parser does not expand variables.
  It costs nothing here and makes the file safe to hand to other dotenv tooling
  that does.

### Step 5 — `run` ✅ **done**

- Arguments split at `--` and are never reinterpreted. A missing `--` is a usage
  error rather than a guess.
- The profile is merged over the parent environment: **the profile wins for every
  key it defines; everything else passes through; an empty value means "set to
  empty", not "delete"; `PATH` is not special-cased.**
- Launched with `os/exec`, terminal attached. The child shares this process
  group, so the terminal delivers signals to it directly; Gatekeeper ignores
  `SIGINT` while waiting so it cannot die first and discard the child's status.
- **The child's exit code becomes Gatekeeper's exit code**, silently. The
  documented exit-code table applies only to failures *before* the child starts.

*Acceptance:* verified. The fixture child receives the value byte-for-byte while
Gatekeeper's output contains none of it; spaces, `;`, `*`, `$`, `|`, quotes,
backslashes, backticks and dash-prefixed arguments all arrive literal; the child's
exit status is propagated unchanged for 0, 1, 3, 42 and 130; a missing executable
is an external failure (8); a locked vault or unknown profile fails before any
process starts.

**One caveat worth stating in the help text.** Because the child's status is
passed through verbatim, a child exiting `5` is indistinguishable from
Gatekeeper's own "conflict" code. That is the standard wrapper behaviour (`env`,
`sudo` and `timeout` all do this) and it is what makes `gk run` usable inside a
`Makefile`, but it does mean the two code spaces overlap once a process has
started.

### The Windows `.cmd` policy

**Decided: run it, and say so.**

Invariant 6 was doing two jobs, and separating them settles this. What the
invariant actually protects is that `run` never *re-interprets arguments as shell
syntax* — arguments are handed over as a list and never joined into a command
line. That holds in every case, on every platform. Whether a `.cmd` file is started
through `cmd.exe` is a platform fact rather than a policy choice: a `.cmd` file
*is* a shell script, and there is no other way to run it.

Refusing would have imposed a daily papercut on the primary platform for no
security gain, since `npm run dev` typed into a prompt obeys the same quoting
rules. So the runner starts batch shims through `cmd.exe` and writes one line to
standard error:

```text
note: npm.cmd is a Windows batch file, so it was started through cmd.exe
```

The part of the old invariant worth keeping is that it is **never silent** — which
is also why invariant 6 was reworded rather than quietly ignored.

The decision logic lives in `launchArgv(goos, path, args)`, which takes `goos` as a
parameter precisely so the Windows branch is testable from Linux.

### Step 6 — guardrails and sync documentation ✅ **done**

- `gk doctor` checks the vault, the recipients, the identity, its permissions,
  whether any key material has found its way into the vault directory, and whether
  the vault carries ignore rules. **It needs no passphrase**, so it still works
  when the vault will not open and the cause is not yet known.
- `gk doctor --pre-commit [--path DIR]` scans for dotenv files, key files and
  private key material, and exits non-zero if it finds any. **It is a filename and
  content check rather than a Git check**, which keeps it usable as a hook, as a
  plain directory scan, and in tests without shelling out to Git.
- **The recovery path is a real command, not a paragraph.** `--identity PATH` opens
  the vault with a raw age key, bypassing the local identity and the passphrase
  entirely. The cryptography was already proven, but until this existed there was
  no way to hand a recovery key to `gk` at all — so "recovery restores access" was
  only half true. Now it is exercised end to end, including with the local identity
  deleted.
- The README documents the transport choices (Git, a file-sync tool, removable
  media), how to install the hook, and how to get back in with the recovery key.

*Acceptance:* verified. A healthy vault reports every check as `ok` and exits 0; a
removed identity is reported as a failure with a non-zero exit; a directory holding
a `.env` and a `.key` is refused with exit 7 and every finding listed; a clean
directory passes; and the check does not print the contents of anything it flags.

Two things the scanner deliberately does not do, both to keep it installed rather
than disabled:

- **It only matches key material at full length.** Source code, docs and fixtures
  mention `AGE-SECRET-KEY-1` constantly. Only a complete key matches, and a PEM
  header must be followed by real base64 — a header alone is documentation.
- **It allows `.env.example`, `.env.sample`, `.env.template` and `.env.dist`**,
  because a guard that flags files you are supposed to commit is a guard people
  learn to bypass.

The filename check is not redundant with the content check: a Gatekeeper identity
is passphrase-encrypted, so its bytes are opaque and the filename is the only
signal that identifies it.

### Step 7 — additions after first use ✅ **done**

Four things requested once the tool was usable, all smaller than what came before.

- **`gk use DIR`** — closes a second-machine gap that only appeared when the flow
  was actually walked through. `init` records a default vault, but `init` cannot
  run against a vault that already exists, so a new machine had no way to stop
  passing `--vault` on every command, and the error message pointed at a command
  that would refuse.
- **`gk sync`** — the plan deferred this with "implement it only if repeated
  personal use proves valuable." It did. It is a wrapper, not an engine: three
  git commands with argument arrays, a commit message built only from profile
  names, and a hard stop with recovery instructions when ciphertext cannot be
  merged. It is also the **only** command that touches the network.
- **`gk passwd`** — re-encrypts the identity under a new passphrase. The old
  passphrase is verified first, so it cannot be used to take over a vault you
  cannot already open, and the new key file is swapped in atomically so an
  interruption leaves the old passphrase working rather than none.
- **`gk flag` / `gk unflag`** — mark a key as exposed. Gatekeeper cannot *detect*
  a leak and never will, so this is the user telling it. Replacing the value
  clears the flag automatically; re-entering the same value does not, because
  that would silence the warning without anything having been fixed. The flag
  lives inside the encrypted payload, so a note like "pasted into #eng-secrets"
  never reaches the repository.

*Acceptance:* verified. `gk sync` round-trips between two real clones and stops
on a conflict with actionable instructions; the generated commit message contains
profile names and nothing else; `gk passwd` makes the old passphrase fail and the
new one work, and a refused change leaves the original working; a flagged key
shows in `list` and `doctor`, survives a reload, is encrypted at rest, and clears
when the value changes.

---

## 7. Windows-first requirements

Windows is the primary platform. The original design assumed POSIX; these are the
differences that change the design rather than a constant.

1. **`os.Chmod` is not access control.** On Windows it only toggles the read-only
   attribute; a "0600" identity can still be readable by other local users.
   Copying the POSIX permission check across would report safety that does not
   exist. The fallback is requiring the identity to live under the per-user
   profile, which Windows already ACLs. Explicit DACL hardening is a later task.
2. **`os.Rename` is not atomic-by-default.** It fails with a sharing violation
   when Defender, the search indexer, an editor, or a sync client holds the
   destination open. This needs a bounded retry; `ReplaceFile`/
   `FILE_RENAME_INFO` is the proper fix. Without it, ordinary `set` operations
   fail intermittently.
3. **`flock` is Unix-only.** The better cross-platform lock is opening the lock
   file with exclusive share mode, which the OS releases automatically when the
   process dies — so there are no stale locks and no staleness heuristic at all.
   This is better than the POSIX-shaped "PID file plus creation time" the original
   design described.
4. **`.cmd` and `.bat` shims cannot be launched by `CreateProcess`.** On Windows
   `npm`, `yarn` and `tsc` are `.cmd` files, so the flagship example
   `gk run demo -- npm run dev` hits this immediately. Resolved by separating the
   two things invariant 6 protects — see the policy below. A batch shim is started
   through `cmd.exe`, and Gatekeeper says so on standard error.
5. **If Git is used, the vault must be marked binary.** Git for Windows defaults
   to `core.autocrlf=true`, which rewrites line endings in files it believes are
   text. Applied to ciphertext that silently corrupts the vault, surfacing later
   as "not decryptable by this identity" — indistinguishable from a wrong key.
   `.gitattributes` marks `*.age` and `*.key` as binary.

All of this lives in `internal/platform`, which is a separate module precisely
because the Windows implementation is a different algorithm, not a different
constant.

---

## 8. Testing strategy

The interface of each deep module is its primary test surface.

**Unit** — name and variable validation; versioned JSON decoding including
duplicate keys, unknown fields and trailing content; environment merge rules;
argument handling; error-to-exit-code mapping; recipient validation.

**Module** — vault create/read/change against a temporary directory; age round
trips with generated identities; wrong identity and corrupt ciphertext; atomic
write failures injected at each stage; permission validation; runner injection
without shell interpolation; passphrase encryption round trip and wrong-passphrase
failure.

**End to end** — init, set a fake value, list its name, run a fixture process;
prove the ciphertext and captured logs contain no canary; import/export round trip;
a second machine decrypting a vault produced by the first using only the copied
identity and the passphrase; the recovery identity decrypting without any device.

Tests use distinctive canary values and scan every artifact for disclosure. Real
credentials are never used, in any test, ever.

Passphrase tests derive keys with scrypt at age's fixed work factor, and the `run`
tests start real child processes. The suite therefore takes about a minute, and
around ten minutes under `-race` — the `cli` package dominates both, because almost
every test there opens a vault.

That is expected and must not be "optimised" by weakening the KDF in tests. The
slowness *is* the protection against an attacker who has the file, and a fast test
suite is not worth a weak vault. Tests cannot be made parallel to claw the time
back either, because they isolate the config directory through environment
variables, which `t.Parallel` forbids.

The practical consequence: `go test ./...` is the normal loop, and `-race` is worth
running before a release rather than on every save.

---

## 9. Security review checklist

Run before every tagged build.

- [ ] No real credentials in fixtures, examples, commits, or CI variables.
- [ ] `go test -race ./...` passes.
- [ ] Canary values appear in no log, stream, filename, or test-produced history.
- [ ] The identity file is passphrase-encrypted, and nothing writes a raw key.
- [ ] Private identities are outside the vault directory.
- [ ] Plaintext writes happen only through `export`, or to the explicitly named
      recovery destination. *(Audited: those are the only two paths in the codebase
      that write a secret in the clear. The recovery key has to be readable to be
      usable offline, which is why it is the one documented exception.)*
- [ ] No code path puts a passphrase into an environment variable or an argument.
      *(Audited: there is no `os.Setenv` in the codebase at all, and `VaultRef`
      never reaches the runner.)*
- [ ] `run` never joins arguments into a command line, and never starts a shell
      without announcing it.
- [ ] No code path puts a passphrase in an environment variable or an argument.
- [ ] Errors never wrap upstream plaintext-bearing values.
- [ ] Unsupported format versions fail closed.
- [ ] Recovery has been tested, not merely documented. *(Verified end to end:
      `--identity` with the local identity deleted recovers both names and values.)*
- [ ] Windows, macOS and Linux all build and vet clean.
- [ ] Dependencies are minimal and pinned.

---

## 10. Definition of done for v0.1

v0.1 is complete when this sentence is true:

> On a fresh machine, clone or copy the vault, place the passphrase-encrypted
> identity, and run `gk run demo -- <command>`; the command sees the right
> variables, and the copied directory contains no plaintext.

Specifically:

1. One executable, no runtime, no service, no account.
2. `init` produces a vault, a passphrase-protected identity, and a printed
   recovery key.
3. Values can be entered without touching shell history or arguments.
4. Names can be listed without revealing values.
5. An ordinary development command runs with a profile injected.
6. The vault moves to a second machine and works there.
7. The recovery identity restores access without any device.
8. All security invariants have automated regression tests.
9. Known limitations are stated in the README and in `--help`.

---

## 11. Deferred and non-goals

Not in v0.1, and not to be started earlier:

device add/remove; `show`; MCP; a web
or desktop UI; a background daemon; a session cache for the passphrase; OS keychain
integration; hardware keys; hosted accounts; team sharing; mobile; browser
extension; automatic rotation; a plugin system; self-update.

Also explicitly out, permanently: becoming a general password manager, and any
form of arbitrary secret retrieval over a network interface.

---

## 12. Open decisions

| Decision | Notes |
| --- | --- |
| **WSL or a separate Linux box** | Determines whether the Linux machine shares or duplicates the Windows identity, and how paths resolve. |
| **Vault transport** | `gk sync` now covers Git. A file-sync tool still works and needs no code — the vault is a directory. No further adapters are planned. |
| **Maximum encrypted profile size** | Unbounded in v0.1; the envelope already caps plaintext at 1 MiB. |
| **License** | Unselected. |

---

## 13. Where the code is now

**All six steps are done.** Every v0.1 command is implemented and tested.

```text
cmd/gk/                  entry point
internal/cli/            Cobra commands; exit-code mapping; passphrase input
internal/app/            use cases: Init, Set, List, Profiles, Import, Export,
                         Environment, Doctor
internal/identity/       key generation, passphrase-protected storage, permissions
internal/envelope/       the only place age is referenced
internal/vault/          profiles, strict decoding, atomic writes, metadata
internal/dotenv/         a parser that never evaluates, and lossless formatting
internal/guard/          finds secrets that are about to be committed
internal/platform/       the POSIX/Windows seam (build-tagged)
internal/runner/         child process launch and environment merge
```

The §18 vertical spike has been deleted. It validated `profile -> age -> safe
persistence -> decryption -> child environment` and scanned for plaintext
disclosure, and the `app` and `cli` tests now cover that ground against the real
commands. Three checks it did make that nothing else did were ported into
`internal/vault/vault_test.go` first: an unauthorized identity cannot read a
profile, a failed write leaves no temporary file behind, and the profile decoder
rejects hostile payloads. The last two were rewritten in the process — the
temp-file check had never actually been able to fail, because a *successful* write
renames the temp file into place, so only the failure path exercises the cleanup.

Dependencies: `filippo.io/age`, `github.com/spf13/cobra`, `golang.org/x/sys`
(Windows), `golang.org/x/term`. Nothing else. Keep it that way — for a tool that
holds keys, every dependency is code running next to your decrypted vault.
