# Gatekeeper — Status

**This is the front door. The plan itself is
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md)** — it is authoritative and
current, and it folds in every decision settled during design. Read it next.

[`ARCHITECTURE.md`](ARCHITECTURE.md) holds the deeper technical design. Its
security invariants are requirements, not plans; where anything disagrees with the
plan, the plan wins except for those invariants.

Last updated: 2026-09-17

## What this is

A local-first CLI vault for project environment variables. Profiles are encrypted
with `age`, the encrypted directory is copied between machines by whatever
transport you like, and `gk run PROFILE -- command` injects a profile into a child
process so no plaintext `.env` is written. A personal tool, not a product: no
service, no subscription, no account.

## Where the work stands

| | |
| --- | --- |
| `gk init` | **Works**, with tests |
| Identity storage | Outside the vault, written `0600`, verified no key material inside the vault |
| Passphrase protection | **Works** — scrypt-encrypted at rest, armored, never read from an environment variable or an argument |
| `gk set` / `gk list` | **Work** — no-echo entry, names only, `set` creates the profile on first use |
| `gk import` / `gk export` | **Work** — bulk entry: one command, one passphrase, every key. Export writes `0600` and warns |
| `gk run` | **Works** — injects a profile into a child process, no shell, child's exit code passed through |
| `gk doctor` | **Works** — checks the vault and identity without needing the passphrase; `--pre-commit` refuses to commit secrets |
| `gk sync` | **Works** — pull, commit, push. Stops with recovery instructions when ciphertext cannot be merged |
| `gk passwd` | **Works** — re-encrypts the identity in place; a refused change leaves the old passphrase working |
| `gk flag` / `gk unflag` | **Works** — marks a key as exposed; replacing the value clears it |
| Recovery | **Works end to end** — `--identity recovery.key` opens a vault with the local identity deleted |
| Two machines | **Verified over a real git clone**, both directions, with the pre-commit guard installed |

All six v0.1 commands are implemented, plus `doctor` and the recovery path. **The
v0.1 build is feature-complete** and the security-review checklist in §9 of the
plan has been run.
| End-to-end path | Covered by the `app` and `cli` tests — vault → age encryption → safe persistence → decryption → child environment, including a scan for disclosure |
| Tests | `go test -race ./...` green across all packages |
| Builds | Windows, macOS and Linux all compile and vet clean |
| Git | Repository initialised, on branch `refactor/code-standards`; nothing pushed |

## What is next

**Feature-complete, plus the three additions: `gk sync`, `gk passwd`, and key
flags.** Twelve commands.

What remains:

1. **Use it on two of your real machines.** The flow is now verified over a real
   `git clone` in both directions, including that the pre-commit guard does not
   block legitimate vault commits. What is still untested is a copy between two
   actual computers over a network — the one thing that cannot be simulated here.
2. **Per-machine keys** instead of one shared identity. Deliberately deferred for
   v0.1; the recipient list already supports several keys, so it is additive.

The Windows `.cmd` question is **settled**: a batch shim is started through
`cmd.exe`, because that is the only way to run one, and Gatekeeper says so on
standard error rather than doing it silently. See the policy in §6 of the plan.

## The security model in six lines

1. Profiles are encrypted to a **random** age key. The ciphertext is uncrackable,
   so the synced directory is safe to copy anywhere.
2. The **private key file** is encrypted with a passphrase, separate from the
   profiles. This is what replaces full-disk encryption.
3. The **offline recovery identity** is a second, independent key stored on paper
   or removable media. It is also the backstop if the passphrase is forgotten.
4. **Malware running as you defeats all of this.** Nothing here fixes that.
5. **A weak passphrase is the one failure mode to avoid.** Five or six random
   words; not a password used elsewhere.
6. **Operational mistakes are the real risk** — not the cryptography. Committing a
   key, exporting a `.env` and forgetting it, pasting a value into a chat.

Full detail, including the threat table, is in §3 of the plan.

## Open decisions

The Windows `.cmd` shim policy (blocks `run`), whether the Linux machine is WSL or
a separate box, and the license. See §12 of the plan.

## Note on the local toolchain

`.toolchain/` contains a Go toolchain downloaded into the repository so the
project could be built without root or a system install. It is gitignored and
disposable; delete it once Go is installed normally.
