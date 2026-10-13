# Security model — public encrypted synthetic CI

## What remains public

The `SUAS-STEM/ci-relay-lab` source tree is public. Windows/Linux GitHub-hosted runners execute **only** the fixed synthetic source; the source allowlist and pinned toy program SHA-256 hashes in `tools/public_guard.py` enforce this. Workflow run metadata, job logs, build context, and the public encryption recipient are publicly visible. Public job logs contain ciphertext, not plaintext executable or synthetic diagnostic output.

No public build receives source from a private repository, a release-writing credential, the age private key, or GitHub credentials from the Pi. The workflow has `contents: read` only and checkout is `persist-credentials: false`.

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
This additional result-signing step has local failure-path tests but is not
part of the earlier successful full Windows build #38478171900.
The successful synthetic proof is public Actions run #38478171900; the
resulting binary/log exist only in private Release `opaque-ci-38478171900`.

The PowerShell subprocess has the public `GH_TOKEN` and `GITHUB_TOKEN`
environment variables removed, but the parent runner process still holds the
public repository's release-upload token. This **does not provide a strong OS
isolation boundary** against malicious source or scripts. The protocol is an
experimental demonstration; it is not approved for confidential production
source, credentials, or unrelated third-party projects.

- The original public fixture uses a read-only `GITHUB_TOKEN`. The separate encrypted MSVC worker has **public-repository** `contents:write` permission to exchange short-lived encrypted prerelease assets; it does not receive any PRIVATE source or Release repository credential. This is a narrower trust boundary, not an isolated enclave. A dedicated repository-scoped GitHub App token should replace the Pi's broad personal token for unattended orchestration.
- Source confidentiality cannot be achieved if proprietary GCS code is built on a public GitHub-hosted runner, even if GitHub Release publication is private. Use a trusted private execution environment for such builds.
- Ciphertext transport in **public** workflow logs means those encrypted bytes may be retained under GitHub's log-retention policy. No Actions artifacts are created; GitHub run logs are a separate storage class.
- If the Pi or dispatcher dies before decrypting a run, its one-time age identity is lost. Rerun CI with a new key; ciphertext logs alone cannot restore the key.
- Encryption and SHA-256 detect ciphertext corruption but do **not independently attest runner honesty**. The GitHub-run/job identity and pinned toy source provide context. Future confidential build systems should use signed provenance with a durable offline-verifiable trust root.
- The private repository's exact-release verifier checks tag, source run/commit, workflow, job outcome, asset count and SHA-256. GitHub administrators with sufficient write access can still mutate tags and releases; plan for immutable external signed attestations.
- The Pi archive currently has Unix file permissions, not disk-level encryption or an independent offsite backup. A stolen SSD or compromised privileged account can expose its plaintext private-release assets.
- The public fixture contains a deliberately generated, random synthetic canary to test accidental plaintext logging; it does not use proprietary secrets.

## Source and release review

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

The approved public CI workflow is manual, `main`-only, and restricted to the approved actor. The repository's protected `main` requires an independent reviewer and the `public-source-gate` check. The one-off temporary integration workflow used during the live proof has been removed; do not re-enable it.

The previous artifact-ZIP upload and signer job were **retired** in favor of ciphertext-in-job-log transport plus Pi-controlled private Releases. Do not assume Sigstore attestations from the retired workflow apply to the new mechanism. Separate signed provenance remains future work.
