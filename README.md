# Gatekeeper

Gatekeeper is a local-first command-line vault for project environment variables.
It gives you one encrypted source of truth that can move between your computers
without repeatedly recreating `.env` files.

> **Status:** early implementation. `gk init` works; the rest of the vault
> workflow is not built, there is no release, and this has not been externally
> security audited.

## The problem

Development secrets tend to end up scattered across ignored `.env` files,
shell history, notes, chat messages, and old computers. Moving to another
computer means finding and re-entering every API key, database URL, and token.

Gatekeeper is intended to replace that workflow with:

```text
one encrypted vault -> sync ciphertext -> unlock on an approved device
```

It is not intended to become an enterprise secrets platform. The first version
is a personal developer tool with no hosted service and no subscription.

## Product principles

- **Local first.** Secret encryption and decryption happen on your computer.
- **Encrypted at rest and in transit.** Sync providers only receive ciphertext.
- **One executable.** Users should not need Node, Python, Docker, SOPS, or an
  always-running server.
- **No permanent `.env` by default.** Prefer injecting variables into a child
  process with `gk run`.
- **Explicit plaintext operations.** Showing or exporting values should be
  obvious and difficult to do accidentally.
- **Established cryptography.** Use the Go implementation of `age`; do not
  invent encryption algorithms or protocols.
- **Recoverable, not magical.** A user must retain at least one authorized
  device key or an offline recovery key.
- **Small before clever.** CLI first; synchronization helpers, MCP, and a UI
  come only after the vault workflow is reliable.

## Proposed experience

Initialize a vault. This sets a passphrase, writes your identity outside the
vault, and prints an offline recovery key exactly once:

```bash
gk init --vault ~/gatekeeper-vault
```

Add values. `set` prompts without echo, keeps the value out of your shell history
and out of the process arguments, and creates the profile on first use:

```bash
gk set website-dev DATABASE_URL
gk set website-dev OPENAI_API_KEY
```

Run a program without creating a plaintext `.env` file:

```bash
gk run website-dev -- npm run dev
```

Inspect the vault without revealing values:

```bash
gk list website-dev
```

Bring secrets in from, or write them out to, an ordinary dotenv file:

```bash
gk import website-dev .env.local
gk export website-dev --output .env
```

`export` is intentionally separate from ordinary listing and execution, warns
first, and refuses to write to standard output without an explicit dangerous flag.

The `show` and `export` commands are intentionally separate from ordinary
listing and execution.

## Commands

**Version one is six commands:**

| Command | Purpose |
| --- | --- |
| `gk init` | Create a vault, a passphrase-protected identity, and an offline recovery identity |
| `gk set PROFILE KEY` | Prompt without echo and store one value |
| `gk list PROFILE` | List variable names, never values |
| `gk run PROFILE -- COMMAND` | Run a child process with the profile injected |
| `gk import PROFILE FILE` | Import a dotenv file into an encrypted profile |
| `gk export PROFILE --output FILE` | Write a plaintext dotenv file after warning |

**Later, once the above is trusted in daily use:** `gk profile create`,
`gk profile list`, `gk unset`, `gk show`, `gk passwd`, `gk doctor`, and recipient
management (`gk device …`). These are deferred deliberately, not forgotten — see
§11 of [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md).

## How it works

Gatekeeper uses the Go [`age`](https://pkg.go.dev/filippo.io/age) library for file
encryption. Each computer gets its own age identity:

```text
recipient/public key -> may encrypt data for that device
identity/private key -> may decrypt data on that device
```

Each profile is stored as a separate encrypted file. A profile is encrypted to
all authorized device recipients plus an offline recovery recipient. Adding or
removing a device causes the current profile files to be decrypted locally and
re-encrypted to the new recipient set.

The encrypted directory can be synchronized with Git, Syncthing, a USB drive,
or another file synchronization system. Git is the first supported workflow,
but it is transport rather than a security dependency.

## Proposed vault layout

```text
.gatekeeper/
├── config.json                # non-secret local configuration
├── devices.json               # device names and public recipients
├── profiles/
│   ├── website-dev.age        # encrypted profile
│   └── website-production.age
└── .gitignore                 # excludes local identity and transient files

~/.config/gk/
└── identities/
    └── <vault-id>.key         # private device identity; never synchronized
```

Profile names and device names are metadata in the initial design. Values and
variable names inside each profile are encrypted. Hiding profile names can be
considered later if it proves useful.

## Moving to another computer

**There is no sync feature, and nothing to configure inside Gatekeeper.** The
vault is a directory. Whatever you already use to copy a directory — Git,
Syncthing, `scp`, a USB stick — *is* the sync. Only ciphertext travels, so the
transport is not a security decision and Gatekeeper is not in the loop.

On the new machine:

```sh
# 1. Get the vault directory there, however you like
git clone <your repository> ~/gatekeeper-vault

# 2. Point Gatekeeper at it, once, so no command needs --vault
gk use ~/gatekeeper-vault

# 3. Copy the identity file across by hand, once:
#      from  <old machine>/.config/gatekeeper/identities/<vault-id>.key
#      to    ~/.config/gatekeeper/identities/<vault-id>.key
#    (Windows: %LOCALAPPDATA%\gatekeeper\identities\)

# 4. That is the whole setup
gk list
gk run website-dev -- npm run dev
```

Step 3 is the only thing that never travels through Git or any sync tool, and it
happens once per machine. After that, every new secret arrives with the directory.
(`gk init` records the default vault for you, so step 2 is only needed on a machine
that did not create the vault.)

### Choosing a transport

| Transport | Notes |
| --- | --- |
| **Git** | `git init`, commit, push. Installed everywhere already, and gives version history. Remember the repository is public to anyone you grant access — which is fine, because it is ciphertext. |
| **A file-sync tool** (Syncthing, a NAS, a cloud drive) | Simplest to live with: it just copies, and there is no history to worry about. Two caveats — point it at the vault directory only, and if the tool keeps its own version history, remember deleted secrets may live there. |
| **A USB stick or `scp`** | Perfectly reasonable for occasional moves, and the least you can possibly depend on. |

Whichever you pick, Gatekeeper is not in the loop, so there is nothing to
configure inside it:

```sh
cd ~/gatekeeper-vault
git add -A && git commit -m "Update profiles" && git push
```

### Installing the guardrail

Before you commit to a repository that also holds the vault, install the check
that refuses to commit a secret:

```sh
printf '#!/bin/sh\nexec gk doctor --pre-commit\n' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

It scans the directory for dotenv files, key files, and private key material, and
exits non-zero if it finds any. `gk doctor` on its own checks the vault, the
identity and its permissions, and needs no passphrase — so it still works when the
vault will not open.

### Getting back in

If every machine is lost, or the passphrase is forgotten, the offline recovery key
printed by `gk init` restores access. It is a separate key and it is deliberately
*not* passphrase-protected — which is why `gk init` insists on a destination it can
actually be delivered to, and refuses to run when there is none.

Point `--identity` at it and the local identity is bypassed entirely:

```sh
gk list website-dev --identity ~/safe/recovery.key
gk export website-dev --identity ~/safe/recovery.key --output restored.env
```

That is also the answer to "I forgot my passphrase": the recovery key is the way
back in, and from there you can re-import into a fresh vault with a new passphrase.

Per-machine identities and recipient management are deliberately deferred: the
recipient list already supports several keys, so adding them later is additive.

## Security boundaries

Gatekeeper protects secrets stored in the synchronized vault. It cannot protect a
secret after an authorized process receives it.

In particular:

- A program launched by `gk run` can read its environment.
- A malicious dependency or modified project can print or transmit variables.
- A sufficiently privileged local attacker may inspect process memory or the
  child process environment.
- `show` exposes a value to terminal scrollback and potentially recording
  software.
- `export` creates a plaintext file whose lifecycle Gatekeeper cannot control.
- Removing a device does not revoke its ability to decrypt old Git revisions
  that were encrypted for it. Compromised credentials must be rotated.

MCP integration therefore will not provide a generic `get_secret` tool. A later
MCP version should expose approved profiles and configured tasks, with clear
warnings that an agent able to modify executed code may still cause that code
to reveal its environment.

## Technology choices

- **Go** for a fast, cross-platform, single-binary application.
- **Cobra** for command structure, help, and shell completion.
- **`filippo.io/age`** for encryption and device recipients.
- **JSON inside encrypted profiles** for a versioned, inspectable data model.
- **Git as an optional sync adapter**, not as the source of truth for security.
- **Go's standard testing package** for unit and integration tests.
- **GoReleaser** when binary distribution becomes necessary.
- **Official MCP Go SDK** only after the core CLI is stable.

There is deliberately no database, web frontend, hosted backend, or account
system in the first version.

## Non-goals for version one

- Enterprise teams, roles, and organization policies
- A hosted Gatekeeper cloud
- Browser password autofill
- Password generation and general password-manager replacement
- Automatic credential rotation
- Mobile applications
- Cross-device real-time synchronization
- Conflict-free concurrent editing
- Arbitrary secret retrieval through MCP
- Protection from a compromised operating system

## Development status

There is no release. `gk init` works: it creates a vault, a device identity, and
an offline recovery identity, and refuses if any private key would land inside the
vault directory. The remaining commands are not built. A vertical spike proves the
load-bearing path — profile → age encryption → safe persistence → decryption →
child environment — and scans for plaintext disclosure.

**Start with [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md)** — it is
the plan, and it is authoritative. It carries the security model, the build order,
the acceptance criteria, and what is deliberately not being built.

[`docs/STATUS.md`](docs/STATUS.md) is the short version: where the work stands and
what comes next. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) is the deeper
technical design, and its security invariants are requirements rather than plans.

## License

No license has been selected yet. Choose one before accepting external
contributions or publishing releases.
