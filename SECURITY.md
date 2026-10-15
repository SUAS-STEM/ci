# Security model — public encrypted synthetic CI

## What remains public

The `SUAS-STEM/ci-relay-lab` source tree is public. In the **original fixture workflow**, Windows/Linux runners compile only the fixed synthetic source; the source allowlist and pinned toy program SHA-256 hashes in `tools/public_guard.py` enforce this. The **separate experimental opaque MSVC workflow** decrypts the synthetic private staging project's CMake source inside its public Windows runner. Workflow run metadata, job logs, and public encryption recipients are visible. The tested public job logs contained no synthetic private compiler output or executable paths.

The original fixture does not receive private repository source or private credentials. Its workflow has `contents: read` only. The distinct opaque MSVC worker deliberately receives **encrypted source from a private staging repository**, and decrypts it during its tokenless build phase. Its bootstrap/publish phases have `contents: write` scoped to its own PUBLIC repository; the workflow never receives private source-repository or private-Release credentials from the Pi. Neither workflow uses `actions/upload-artifact`. This distinction is critical when assessing proprietary-source confidentiality.

## Ciphertext transport (no Actions artifacts)

Each Pi-triggered run generates an ephemeral X25519 `age` identity in a sealed anonymous Linux memfd. Best-effort memory locking, non-dumpable process state, and disabled core dumps reduce trivial private-key exposure; these do not make a compromised kernel or root attacker harmless. The Pi sends **only** the public recipient to the public workflow.

The fixed job encrypts its captured diagnostic output and compiled toy executable to that recipient, then prints two base64-wrapped `age` ciphertext records to the GitHub job log. The envelope includes SHA-256 for truncation/corruption detection and limits size. The private Pi identity is never sent to GitHub. The runner can see the toy source and plaintext build output *before encryption*.

The Pi independently retrieves both raw job logs from GitHub, checks run origin and actor, branch, commit, exact two successful OS jobs, exact ciphertext headers/hashes, and decryption. Decrypted payloads are checked against the run ID, source SHA, trace, recipient digest, platform, canary uniqueness and expected synthetic success. The Pi also scans the public job logs for unexpected plaintext test canaries.

The public runner does **not** upload Actions artifacts; the private Release is published *from the Pi* only. A finished private Release is downloaded again and SHA-256-verified, then durably archived on Pi via the private repo's mirror utility. GitHub Release assets are normal private-repository assets and are visible to authorized private repository users; this is not end-to-end encryption against those users.

## Controls and residual risks

### Encrypted synthetic-source/MSVC test (distinct threat model)

`secure-opaque-build.yml` is separate from the original **public fixture only**
`fixture.yml`. The opaque worker checks out only reviewed public relay code,
but it then explicitly decrypts and compiles an encrypted synthetic CMake
source bundle and private `.ps1` script. Its temporary workspace and Windows
compiler contain source plaintext. GitHub/Microsoft runner infrastructure,
compromised runner execution, and maintainers able to alter trusted public
workflow code are not excluded from the trust boundary.

The private coordinator generates an ephemeral age recipient for results;
the Windows worker generates a different ephemeral age keypair for inputs.
The Windows job must have `id-token:write` permission and publishes a GitHub
OIDC-signed JWT attesting its one-time input recipient. The private coordinator
checks GitHub's signing keys, run/repository identity and a custom audience
hash binding the nonce, private commit and both ephemeral recipients **before
source upload**. Unsigned or substituted public Release recipients are refused.
Only public recipients and authenticated age ciphertext are transported in
short-lived PUBLIC prerelease assets. The **verbatim combined** compiler
stdout/stderr bytes and exit-code/log-hash status are encrypted separately.
An additional OIDC JWT signed by GitHub binds the exact raw compiler-log hash,
compiled executable hash, and process exit code to the same approved runner,
workflow revision, source commit, and one-time keys. The private coordinator
rejects mismatched JWTs before printing diagnostics or publishing outputs.
This additional result-signing step has local failure-path tests and passed
the later successful full Windows build #38493277635.
The GitHub-signed return-channel handshake and MSVC compilation subsequently
passed in public run #38484774417; its private Release step initially failed
because GitHub's draft listing was delayed. The private publisher now retries
read visibility and rejects unexpected assets without overwriting them. A
subsequent complete private Release publication was verified in public build
#38493277635 and private Release `opaque-ci-38493277635`.

The optional daily PUBLIC cleanup workflow uses a PUBLIC-repo-only write
token to remove recognized ciphertext-only prereleases older than 24 hours.
It refuses changes to release ownership, asset digests and expected filenames,
and skips an active public runner. It never accesses private source, artifacts,
or credentials. This is a best-effort recovery measure, not a guarantee of
immediate deletion after a catastrophic coordinator failure.
The successful current synthetic proof is public Actions run #38674511480;
its binary and diagnostic log are retained in the private Release.

The revised three-step public workflow publishes its signed ephemeral public
recipient with a scoped PUBLIC Release token; a separate build step downloads
the public ciphertext anonymously and executes the PowerShell/MSVC subprocess
without `GH_TOKEN` or `GITHUB_TOKEN` in **either its own transport Python
process or the PowerShell child process**. The trusted PowerShell launcher
also unsets job-scoped OIDC request credentials, runtime tokens and GitHub
workflow-control paths before it starts Python; the Python entry point refuses
to compile if these values remain. This is best-effort process hygiene and
**does not** remove credentials from privileged hosted-runner infrastructure
or constitute a sandbox. This replaces an earlier optional
incremental ciphertext streaming implementation that held a PUBLIC-only
release token in its transport parent while compiling. The compiler subprocess
filters GitHub Actions control-file paths, OIDC/runner variables, known token
and credential variable names, and relay metadata while retaining ordinary
Windows/MSVC execution settings. Local tests enforce that filtering, but a
same-user or privileged process can still inspect other processes and the
runner infrastructure. It then deletes the plaintext build workspace and
one-time private key before a final step uploads encrypted results using the
PUBLIC token. This reduces direct token exposure but **does not provide an OS
isolation boundary** against malicious source or scripts. The staged version
has passed local tests **and** a real hosted Windows/MSVC build, public run
#38674511480, which returned signed encrypted output to verified private
Release `opaque-ci-38674511480`. It remains experimental and is not approved
for confidential production source. The small private GitHub Actions caller
has an on-demand, memory-capped Pi Docker runner implementation and a
successful separate runner smoke test, but has not completed a full relay run.
Incremental ciphertext log streaming passed a prior public hosted test
(#38600642017), but the **current tokenless compile stage** intentionally
returns compiler output only after completion. The final GitHub-signed log hash
remains authoritative. This latest token-free revision was validated in
hosted public Windows/MSVC run #38674511480, including checks that the public
log contained no synthetic private output marker and created zero Actions
artifacts. The private GitHub Actions coordinator is still not enabled.

- The original public fixture uses a read-only `GITHUB_TOKEN`. The separate encrypted MSVC worker has **public-repository** `contents:write` permission to exchange short-lived encrypted prerelease assets; it does not receive any PRIVATE source or Release repository credential. This is a narrower trust boundary, not an isolated enclave. A dedicated repository-scoped GitHub App token should replace the Pi's broad personal token for unattended orchestration.
- Source confidentiality cannot be achieved if proprietary GCS code is built on a public GitHub-hosted runner, even if GitHub Release publication is private. Use a trusted private execution environment for such builds.
- Ciphertext transport in **public** workflow logs means those encrypted bytes may be retained under GitHub's log-retention policy. No Actions artifacts are created; GitHub run logs are a separate storage class.
- If the Pi or dispatcher dies before decrypting a run, its one-time age identity is lost. Rerun CI with a new key; ciphertext logs alone cannot restore the key.
- Encryption and SHA-256 detect ciphertext corruption but do **not independently attest runner honesty**. The GitHub-run/job identity and pinned toy source provide context. Future confidential build systems should use signed provenance with a durable offline-verifiable trust root.
- The private repository's exact-release verifier checks tag, source run/commit, workflow, job outcome, asset count and SHA-256. GitHub administrators with sufficient write access can still mutate tags and releases; plan for immutable external signed attestations.
- The Pi archive currently has Unix file permissions, not disk-level encryption or an independent offsite backup. A stolen SSD or compromised privileged account can expose its plaintext private-release assets.
- The public fixture contains a deliberately generated, random synthetic canary to test accidental plaintext logging; it does not use proprietary secrets.

## Public reusable workflow definitions invoked by private callers

`.github/workflows/private-reusable-build.yml` is intentionally **public
source code for CI configuration**, not a public hosted job for private
projects. GitHub evaluates the called workflow inside the PRIVATE caller's
execution context. The reusable workflow refuses execution unless the caller
repository is private and the event is on its default branch, and it never
checks out a public build-fixture repo. Callers should pin a reviewed full
commit SHA and configure branch protection on the private source repo.

For external private release destinations, a dedicated narrow publisher
credential is required; the workflow never inherits arbitrary secrets and
never uses `actions/upload-artifact`. The separate caller's private logs can
still contain sensitive compiler diagnostics, so use branch protections and
runner access controls. No cryptographic source secrecy from GitHub-hosted
runner administrators or privileged self-hosted users is claimed. The private
caller also pays for the runner execution, regardless of the reusable
definition being publicly hosted.

## Source and release review

The approved public CI workflow is manual, `main`-only, and restricted to the approved actor. The repository's protected `main` requires an independent reviewer and the `public-source-gate` check. The one-off temporary integration workflow used during the live proof has been removed; do not re-enable it.

The previous artifact-ZIP upload and signer job were **retired** in favor of ciphertext-in-job-log transport plus Pi-controlled private Releases. Do not assume Sigstore attestations from the retired workflow apply to the new mechanism. Separate signed provenance remains future work.
