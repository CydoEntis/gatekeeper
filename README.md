<p align="center">
  <img src="assets/logo.svg" width="128" height="128" alt="Gatekeeper">
</p>

<h1 align="center">Gatekeeper</h1>

<p align="center">
  One encrypted source of truth for your project environment variables —<br>
  on every computer you own, with no service, no subscription, and no plaintext lying around.
</p>

> **Pre-release.** The v0.1 command set is feature-complete and tested, but there
> is no release, and this has not been externally security audited. Read
> [Security model](#security-model) before trusting it with anything that matters.

---

## The problem

Your secrets are scattered across ignored `.env` files, shell history, notes,
chat messages, and an old laptop. Moving to a new machine means hunting down
every API key, database URL, and token and typing it in again.

Gatekeeper replaces that with:

```text
one encrypted vault  ->  sync the ciphertext  ->  unlock on each machine
```

It is a personal developer tool. It is not an enterprise secrets platform, and
there is no hosted service anywhere in it.

## Quick start

```sh
# 1. Create the vault. Prints an offline recovery key exactly once.
gk init --vault ~/gatekeeper-vault --recovery-out ~/safe/recovery.key

# 2. Put a secret in. Prompts without echo; never touches your shell history.
gk set website-dev DATABASE_URL

# 3. Or bring in a whole .env at once.
gk import website-dev .env.local

# 4. See what you have, without seeing any values.
gk list website-dev

# 5. Run something with those variables injected. No .env file is created.
gk run website-dev -- npm run dev
```

`gk init` records the vault as this machine's default, so no later command needs
`--vault`.

## Install

Requires **Go 1.26 or newer**.

```sh
git clone <this repository> gatekeeper
cd gatekeeper
go build -o gk ./cmd/gk
```

Then put `gk` somewhere on your `PATH`. To run the test suite, the linters, and
the cross-compiles exactly as CI would, see [Development](#development).

## Commands

| Command | Purpose |
| --- | --- |
| `gk init --vault DIR` | Create a vault, a passphrase-protected identity, and an offline recovery identity |
| `gk use DIR` | Point this machine at an existing vault, so nothing needs `--vault` |
| `gk import PROFILE FILE` | Import a dotenv file — the bulk entry path |
| `gk set PROFILE KEY` | Prompt without echo and store one value |
| `gk list [PROFILE]` | Name the profiles, or the variables in one. Never values |
| `gk run PROFILE -- COMMAND` | Run a child process with the profile injected |
| `gk export PROFILE --output FILE` | Write a plaintext dotenv file, after warning |
| `gk sync` | Pull, commit locally, push — three ordinary git commands |
| `gk flag PROFILE KEY --note` | Mark a key as exposed until you replace it |
| `gk unflag PROFILE KEY` | Clear that mark without changing the value |
| `gk passwd` | Change the passphrase, re-encrypting the identity in place |
| `gk doctor` | Check the vault and identity; `--pre-commit` refuses to commit secrets |

Every command accepts `gk --help` for the full text.

### Global flags

| Flag | Meaning |
| --- | --- |
| `--vault DIR` | Vault directory. Defaults to `$GK_VAULT`, then the configured default vault |
| `--identity PATH` | Open the vault with this raw age private key instead of the local identity — the recovery path |

### Unlocking

Commands that need to read secrets will prompt for your passphrase with echo
disabled. Two alternatives, both intended for scripts and automation:

| Flag | Where it works |
| --- | --- |
| `--passphrase-file PATH` | Any command that needs the passphrase |
| `--value-file PATH` | `gk set`, instead of prompting for the value |

Both refuse a file that is readable by other local users, and neither will read a
passphrase or a value from an argument or an environment variable — an argument
lands in your shell history and in the process list, which is the exact problem
this tool exists to solve.

### `gk init`

Creates two key pairs: one your machines use, and one recovery key meant to be
stored offline. Every profile is encrypted to both, so losing every computer is
survivable as long as the recovery key survives.

The machine identity is encrypted at rest under your passphrase, so a stolen or
copied key file is useless without it. The recovery key is deliberately **not**
encrypted — it belongs on paper or removable media, and it is also the way back in
if you forget the passphrase. Because it is printed in the clear, `gk init`
insists on a destination it can actually be delivered to, and refuses to run when
stdout is not a terminal.

The passphrase must be at least 12 characters. Under 20 you get a warning, not a
refusal — blocking a short passphrase pushes people toward writing it down, which
is worse.

### `gk set` and `gk list`

`set` prompts without echo, creates the profile on first use, and never accepts
the value as an argument. `list` names profiles, or the variables in one, and
**never** shows a value — the type it prints has no field for one, so it cannot
leak by accident.

```sh
gk list                                  # profiles
gk list website-dev                      # variable names in one profile
```

### `gk import` and `gk export`

`import` is the bulk entry path: one command, one passphrase, every variable. The
file is parsed as data and **never evaluated** — no variable expansion, no command
substitution, no shell — so a file you did not write cannot run code by being
imported. Use `-` as the file to read standard input.

A variable that already exists with a different value stops the import, unless
you pass `--overwrite`.

`export` is the one operation that deliberately produces plaintext. Nothing else
Gatekeeper does writes a secret to disk in the clear, and once that file exists,
its lifecycle is yours rather than Gatekeeper's. It warns, it writes `0600`, it
refuses to overwrite an existing file without `--force`, and it will not write
anywhere at all until you name either `--output FILE` or an explicit `--stdout`.

```sh
gk export website-dev --output .env
```

**Delete it when you are done.**

### `gk run`

Runs a command with the profile's variables added to its environment, so no
plaintext `.env` is ever created. Everything after `--` is passed through
untouched, and no shell is involved, so spaces, quotes, and metacharacters keep
their literal meaning.

```sh
gk run website-dev -- npm run dev
```

The profile wins over your current environment for every variable it defines;
every other variable passes through unchanged. Once the command starts, its exit
status is yours — `gk` exits with the child's code. Gatekeeper's own exit codes
apply only when it fails before starting anything.

On Windows, tools like `npm` and `yarn` are batch files, which cannot be started
directly. Those are run through `cmd.exe`, and Gatekeeper says so on standard
error rather than doing it silently.

### `gk flag`

Gatekeeper cannot detect that a key was exposed — it has no network access, and it
cannot know what you pasted into a chat. So you tell it, and it remembers:

```sh
gk flag website-dev OPENAI_API_KEY --note "pasted into #eng-secrets"
gk list website-dev
#   DATABASE_URL
#   OPENAI_API_KEY   [flagged: pasted into #eng-secrets (2026-09-17)]
#   STRIPE_KEY
```

A flagged key shows up in `gk list` and in `gk doctor` until you replace the
value. **Replacing the value clears the flag by itself**, because a new value is
the rotation. Re-entering the *same* value does not — otherwise retyping a secret
would silence the warning without anything having been fixed. `gk unflag` clears a
flag you decided never mattered.

The flag and its note live inside the encrypted payload, so they travel with the
vault and a note like `pasted into #eng-secrets` never reaches the repository.

Flagging does not rotate anything at the provider. That is still your job.

### `gk passwd`

Re-encrypts the local identity under a new passphrase. The current passphrase is
required, so this cannot lock you out of a vault you can already open. The new key
file is written and swapped in atomically, so an interruption leaves the old
passphrase working rather than leaving you with none.

This does **not** re-encrypt any profiles. They are encrypted to the identity, not
to the passphrase, so the vault is untouched and your other machines are
unaffected. The offline recovery key has no passphrase to change.

### `gk doctor`

With no flags it checks the vault, the identity, and whether secrets are about to
be committed. It does **not** need your passphrase, so it still works when the
vault will not open and you do not yet know why.

| Check | What it means |
| --- | --- |
| vault selected | A vault directory was found |
| vault readable | `manifest.json` and `devices.json` parse |
| recipients readable | Every device recipient plus the recovery recipient parses |
| identity present | A local identity exists for this vault |
| identity protected | It is encrypted at rest, and where it should be |
| no key material in the vault | Nothing in the vault directory looks like a secret |
| vault has ignore rules | `.gitignore` is present |
| no flagged variables | Skipped unless you unlock; needs `--passphrase-file` |

### `gk sync`

Three ordinary git commands run in the vault directory, in order: `git pull`,
then `git add` for the vault's own changed files with a commit if anything
changed, then `git push`.

Staging is limited to the paths the vault owns, so it is **not** `git add -A` —
anything else you happen to keep in that directory is left alone rather than swept
into a commit. A generated commit message contains profile names at most, never
variable names or values. If the pull cannot be merged it stops and explains what
to do rather than guessing.

This is the only command that touches the network, and only when you run it.

## How it works

Gatekeeper uses the Go [`age`](https://pkg.go.dev/filippo.io/age) library. Each
machine has an age identity:

```text
recipient (public key)  ->  may encrypt data for that machine
identity (private key)  ->  may decrypt data on that machine
```

Each profile is a separate encrypted file, encrypted to every authorized device
recipient **plus** the offline recovery recipient. Profiles are not encrypted to
your passphrase; they are encrypted to a random key, and only that key file is
protected by the passphrase. Practically, this means changing your passphrase is
instant and does not touch a single profile.

The vault is a directory of ciphertext. Git, Syncthing, a USB stick, or anything
else that copies files *is* the sync — Gatekeeper is not in the loop, so the
transport is not a security decision.

## Where things live

The vault — everything here is safe to commit, because it is all ciphertext or
non-secret metadata:

```text
~/gatekeeper-vault/
├── manifest.json            # vault id, name, format version
├── devices.json             # device names and public recipients
├── profiles/
│   ├── website-dev.age      # one encrypted file per profile
│   └── website-production.age
└── .gitignore               # excludes local identity and transient files
```

On each machine — **never** synchronized, and the only thing you copy by hand:

```text
~/.config/gatekeeper/            # Linux, macOS
%LOCALAPPDATA%\gatekeeper\       # Windows
├── config.json                  # which vault is the default here
└── identities/
    └── <vault-id>.key           # passphrase-encrypted private identity
```

Profile names and device names are metadata. Values and variable names inside each
profile are encrypted.

## Using it on a second computer

The vault is a directory. Whatever you already use to copy a directory is the
sync. On the new machine:

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

### Choosing a transport

| Transport | Notes |
| --- | --- |
| **Git** | `git init`, commit, push. Already installed everywhere, and gives you history. The repository is readable by anyone you grant access — which is fine, because it is ciphertext. |
| **A file-sync tool** (Syncthing, a NAS, a cloud drive) | Simplest to live with: it just copies. Two caveats — point it at the vault directory only, and if it keeps its own version history, remember deleted secrets may live there. |
| **A USB stick or `scp`** | Perfectly reasonable for occasional moves, and the least you can depend on. |

### Installing the guardrail

Before you commit to a repository that also holds the vault, install the check
that refuses to commit a secret:

```sh
printf '#!/bin/sh\nexec gk doctor --pre-commit\n' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

It scans for dotenv files (`.env`, `.env.*`), key and certificate files
(`.key`, `.p12`, `.pfx`), SSH private keys (`id_rsa`, `id_ed25519`, `id_ecdsa`,
`id_dsa`), and raw age private key material, and exits non-zero if it finds any.

### Getting back in

If every machine is lost, or you forget your passphrase, the offline recovery key
from `gk init` restores access. Point `--identity` at it and the local identity is
bypassed entirely:

```sh
gk list website-dev --identity ~/safe/recovery.key
gk export website-dev --identity ~/safe/recovery.key --output restored.env
```

That is also the answer to "I forgot my passphrase": the recovery key is the way
back in, and from there you can import into a fresh vault with a new passphrase.

Per-machine identities and recipient management are deliberately deferred. The
recipient list already supports several keys, so adding them later is additive
rather than a migration.

## Security model

**What this protects.** The vault at rest and in transit. Profiles are encrypted
with `age` before they are ever written, so a synced repository, a backup, or a
stolen laptop disk yields ciphertext. Your passphrase protects the identity file,
so copying that file alone is not enough. This is what replaces full-disk
encryption for the narrow case of these secrets.

**What it cannot protect.** A secret, once delivered to a program, is that
program's. In particular:

- A program launched by `gk run` can read its own environment.
- A malicious dependency or a modified project can print or transmit variables.
- A sufficiently privileged local attacker can inspect process memory or a child
  process's environment.
- `gk export` creates a plaintext file whose lifecycle Gatekeeper cannot control.
- Removing a device does not revoke its ability to decrypt **old Git revisions**
  that were encrypted for it. Compromised credentials must be rotated.
- Malware running as you defeats all of this. Operational mistakes are the
  dominant real-world risk, which is why listing never shows values, why
  `export` is loud, and why the guardrail exists.

**Plaintext writes are exactly two places:** `gk export`, and the recovery key's
named destination at `gk init`. Nothing else in the tool writes a secret to disk in
the clear.

**On Windows**, permissions are weaker and the tool says so rather than pretending
otherwise. `os.Chmod` only toggles the read-only attribute and does not stop
another local account from reading a file. Gatekeeper therefore requires those
files to live under your per-user profile, which Windows already ACLs to you, and
treats anything else as unsafe. It does not write a DACL. A machine where another
local account can read your profile directory is a machine where your key is
readable.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Failure — an unclassified problem |
| 2 | Usage — a bad flag, a bad name, or no vault selected |
| 3 | Not found — a missing profile, variable, or file you named |
| 4 | Locked — no usable identity, or a passphrase that does not unlock it |
| 5 | Conflict — a revision or synchronization conflict |
| 6 | Integrity — an invalid or corrupted encrypted payload |
| 7 | Permission — an unsafe identity or secret file |
| 8 | External — a sync or child-process startup failure |

Classification is by sentinel, so wrapping an error does not change its code. Once
`gk run` has started a child process, the child's exit code is passed through
verbatim and these codes no longer apply.

## Troubleshooting

**"unsafe file permissions"** — A file you named with `--passphrase-file`,
`--value-file`, or `--identity` is readable by other local users. The error names
the file and the fix: `chmod 600 <file>`.

**"the two passphrases do not match"** — `gk init` and `gk passwd` ask twice when
creating a new passphrase. Nothing has been written at that point; just run it
again.

**"not a Gatekeeper vault"** — The directory has no readable `manifest.json`. If
you are on a new machine, check that step 1 of
[Using it on a second computer](#using-it-on-a-second-computer) actually
completed, and that `--vault` points at the vault directory rather than its
parent.

**The vault will not open and you do not know why** — Run `gk doctor`. It needs no
passphrase, so it still works in exactly the situation where you need it.

**A merge conflict in `gk sync`** — Ciphertext cannot be merged, so Gatekeeper
stops instead of guessing. It prints the recovery steps. Because each profile is
its own file, a conflict is normally narrowed to one profile.

## Development

```sh
go test ./...                                  # the suite
go test -race ./...                            # the suite, with the race detector
go test ./internal/vault/ -run Fuzz            # fuzz seed corpus
go test ./internal/vault/ -fuzz FuzzRoundTrip -fuzztime 30s
```

The suite is deliberately slow: `scrypt` cost is real, and weakening the KDF to
speed up tests would weaken the thing being tested.

Before proposing a change:

```sh
gofmt -s -l ./cmd ./internal      # must print nothing
go vet ./...                      # also: GOOS=windows, GOOS=darwin
staticcheck ./...
govulncheck ./...
GOOS=windows go build ./cmd/gk    # cross-compiles
GOOS=darwin  go build ./cmd/gk
```

Dependencies are kept deliberately small — `filippo.io/age`, `spf13/cobra`,
`golang.org/x/sys`, `golang.org/x/term`, and nothing else. For a tool that holds
keys, every dependency is code running next to your decrypted vault.

## Documentation

| Document | What it is |
| --- | --- |
| [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) | **Authoritative.** The security model, the build order, the acceptance criteria, and what is deliberately not being built |
| [`docs/STATUS.md`](docs/STATUS.md) | The short version: where the work stands and what comes next |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | The deeper technical design. Its security invariants are requirements, not plans |
| [`docs/CODE-STANDARDS.md`](docs/CODE-STANDARDS.md) | Naming, boundaries, error handling, testing, and the commit format |

## Not in version one

- Enterprise teams, roles, and organization policies
- A hosted Gatekeeper cloud
- Browser password autofill
- Password generation, or replacing a general password manager
- Automatic credential rotation
- Mobile applications
- Cross-device real-time synchronization
- Conflict-free concurrent editing
- Arbitrary secret retrieval through MCP
- Protection from a compromised operating system

Also deliberately deferred: `gk profile create`, `gk profile list`, `gk unset`,
`gk show`, and recipient management (`gk device …`). See §11 of the
[implementation plan](docs/IMPLEMENTATION_PLAN.md).

## License

No license has been selected yet. Choose one before accepting external
contributions or publishing releases.
