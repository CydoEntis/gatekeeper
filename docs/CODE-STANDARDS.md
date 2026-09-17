# Gatekeeper code standards

Adapted from the standards used in the author's other projects (Intelligent Notes
/ Knapkn). Those documents assume TypeScript, React, and SQLite; this one says how
the same principles apply to a Go CLI, and what replaces what. Where the two
disagree, this file wins for this repository.

Read alongside [`ARCHITECTURE.md`](ARCHITECTURE.md) (the design and its security
invariants) and [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) (what is being
built, and what is deliberately not).

---

## 1. Names

- **Precise domain names.** `sealedIdentity`, `recipient`, `manifest`. Not `data`,
  `item`, `thing`, or `helper` — those were the words that prompted this file.
  The one survivor is `raw` for the unparsed bytes of a file, which says what it is.
- **Booleans read as assertions**: `isTerminal`, `isShellShim`, `hasFlag`,
  `canRestore`, `usedShell`.
- **Functions read as verbs**: `installVault`, `deliverRecovery`, `parseValue`.
  A constructor may read as a noun (`NewEnvelope`), which is the Go convention.
- **Consistent terminology across packages.** A "profile" is a profile in the
  vault, the CLI, the CLI's help text, and the tests. A "recipient" is never
  called a "device" in one place and a "key" in another.
- **Exported symbols have doc comments**, starting with the symbol's name.
  `go vet` does not enforce this; review does.

## 2. Constants

The rule this file exists because of: **do not repeat a meaningful literal.**

- Permission modes live in `platform.PrivateFileMode`, `PrivateDirMode`,
  `GroupOrOtherBits`.
- Flag names and their help strings live in `cli/flags.go`, once each. Nine
  commands register the passphrase flag; the wording is written down once.
- Doctor check labels live in `app/doctor.go`; they are asserted on by tests, so
  they are identifiers as much as prose.
- Error messages that appear more than once become named constructors —
  `vault.InvalidProfileName` rather than the same `fmt.Errorf` in thirteen places.
- Format shapes are named: `vault.ProfileFileExt`, `identity.identityFileExt`,
  `platform.TempFilePrefix`, `guard.ageSecretKeyLength`.
- A literal is fine when it is genuinely local and appears once. The test is
  whether two places must agree; if they must, it gets a name.

## 3. Functions

- **One job, one level of abstraction.** `App.Init` was 188 lines doing six
  things; it is now an orchestrator over `normalizeInitRequest`,
  `validateInitRequest`, `installVault`, `deliverRecovery`, and
  `recordDefaultVault`.
- **Guard early and return.** Validation happens before the first side effect, so
  a refusal costs nothing — see `validateInitRequest`, which every check runs
  before a single file exists.
- **Avoid deep nesting.** A nested `if/else` that survives review usually wants to
  be a helper with a name.
- **Extract on the second real use, not the first.** No speculative generic
  layers. There is no plugin interface here because there is one adapter.
- **Side effects belong at boundaries**: `platform` for the operating system,
  `envelope` for cryptography, `os`/`exec` for the world.

## 4. Errors

- **Sentinel errors for categories callers branch on** — every `ErrNotFound` in
  this codebase exists because a command or an exit code depends on it. Everything
  else is a plain wrapped error.
- **Wrap with `%w`** so `errors.Is` keeps working, and unwrap deliberately: errors
  from `age` are dropped where the upstream text can quote key material.
- **Never put a secret in an error.** This is why `ProfileEnvironment` has a
  redacting `String()`.
- **Map to exit codes through one table**, `cli.exitCodeGroups`, which mirrors
  `ARCHITECTURE.md` §9. A caller writing a script branches on those numbers, so
  the mapping is a published contract rather than an implementation detail.

## 5. Boundaries

Dependency direction, adapted from the source documents' "dependencies point
inward":

```text
cmd/gk  →  cli  →  app  →  vault · identity · gitsync · guard  →  envelope · platform  →  stdlib
```

- **`cli` never touches age, files, or exec directly.** It parses, calls one
  application operation, renders, and maps an error to an exit code.
- **`app` holds the use cases and performs no terminal I/O.** The passphrase is
  passed in, never prompted for here, which is what lets the whole application
  layer be tested without a terminal.
- **`envelope` is the only package that imports age.**
- **`platform` is the only package that branches on the operating system**, and it
  does so with build tags rather than `runtime.GOOS` checks scattered elsewhere.
- **`dotenv` and `guard` are leaves** with no internal dependencies, so they can be
  tested in isolation.
- **Validate at every boundary**: decrypted payloads, manifest and recipient
  metadata, imported dotenv files, passphrase files, and everything crossing from
  a child process.

## 6. Security

`ARCHITECTURE.md` §8.3 lists the invariants; they are requirements, not
aspirations, and **each one needs a test**. Beyond those:

- **Never execute content.** No `eval`, no shell, no dynamic SQL. The dotenv
  parser is data handling and says so; `run` passes argument arrays, never a
  command line.
- **Plaintext writes happen in exactly two places**: `export`, and the recovery
  key's named destination. Both are explicit, both are tested, and adding a third
  needs a reason written down.
- **Never weaken or skip a legitimate test to make a change pass.** The exit code
  a test asserts, and the canary a test scans for, are the product.

## 7. Testing

- **Test behaviour and contracts**, not implementation details. The vault is tested
  through its interface; the CLI is tested by running it.
- **Deterministic tests.** The clock and the ID source are injected
  (`App.Now`, `App.NewID`) rather than reached for. No test reads a developer's
  home directory or a real identity.
- **Table tests with named cases** for anything with more than two branches.
- **Never real credentials**, in any test, ever. Canary values only, and the suite
  scans its own artifacts for them.
- `t.Setenv` is how tests isolate the config directory, which **forbids
  `t.Parallel`**. That is a deliberate trade: isolation over speed.
- **`go test ./...` is the loop; `go test -race ./...` is for before a release.**
  The suite is slow because scrypt is slow, and the slowness *is* the protection.
  Do not "optimise" it by weakening the KDF.

## 8. Change discipline

- **One slice per change.** A commit should be reviewable as one behaviour and its
  tests.
- **Document consequential decisions** — dependencies, formats, permissions, and
  anything with a privacy or security consequence — in the plan's settled-decisions
  table or in the file where the decision lives.
- **Inspect the diff and the working tree before handoff**, and report what was
  actually verified rather than what was intended.
- **No network calls anywhere** except `gk sync`, which is explicit and runs git.
  No telemetry, no background behaviour, no self-update.

## 9. Commits

```text
<type>(<scope>): <subject>
```

Types: `feat` · `fix` · `refactor` · `docs` · `test` · `style` · `perf` · `build` ·
`ci` · `chore`. Scopes used here: `vault`, `cli`, `crypto`, `identity`, `dotenv`,
`guard`, `sync`, `run`, `docs`, `build`.

Subjects are at most 50 characters, lowercase, imperative, no trailing period. The
body explains *why* only when the reason is not obvious from the diff. Never
narrate the files changed.

Commits contain **no AI or tooling attribution** — no `Co-Authored-By`, no
`Generated-By`, no footer of any kind. The author and committer fields are the only
authorship record.

A commit is created when the user asks for one, not because code changed. Propose
the message and the affected files, then wait. Never `git commit --amend`,
`--no-verify`, `reset --hard`, or `clean -f`.

The three commits made before this document was written do not follow the subject
format. They are not being rewritten, because rewriting history is exactly what
this section forbids.
