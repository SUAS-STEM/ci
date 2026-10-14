# Encrypted public CI relay (synthetic only)

This is the **PUBLIC test repository** for the encrypted Windows/Linux CI transport. Only a pinned, harmless C++ sample is compiled here. A trusted Raspberry Pi holds each one-time decryption key, retrieves encrypted job logs, verifies build identity and contents, and uploads the compiled outputs directly to a **PRIVATE GitHub Release** at [SUAS-STEM/ci-release-vault](https://github.com/SUAS-STEM/ci-release-vault).

**No GitHub Actions artifacts are created or downloaded.** GitHub public workflow logs contain *only age ciphertext* for the test output. The Pi uploads the verified Linux and Windows executables, with checksum sidecars, straight to the private Release. It then synchronizes that private release to its own permanent storage.

The earlier artifact ZIP upload/download, GitHub artifact deletion, and long-term artifact-store code have been removed. The historical Pi archives under `~/ci-artifacts/ci-relay-lab/` are unchanged, but no new runs use that path.

## Operating flow

1. Run `python3 tools/install_age.py` on the Pi to install the pinned, checksum-verified `age` binary.
2. From this repository's **approved `main` branch**, run `python3 -m tools.pi_public_release --left 17 --right -3`.
3. The Pi creates a unique X25519 age keypair in anonymous RAM-backed Linux `memfd`. It dispatches `.github/workflows/fixture.yml` with a random trace, two validated numbers, and the *public* age recipient. Only the fixed synthetic source is built by Windows and Linux hosted runners.
4. Runner output is captured and encrypted to the Pi's public key. Two ciphertext strings (log and binary) appear in each public job log as `CI_RELAY_ENCRYPTED_V1` records. No plaintext test canaries or build output should appear in public logs.
5. The Pi verifies that both GitHub jobs completed successfully, that the run's commit, workflow, actor, branch, run ID, recipient, platform, and synthetic canaries match, and then decrypts both reports locally.
6. **On the Pi only**, the verified binaries are uploaded to a private **draft** GitHub Release; both are downloaded and SHA-256 checked before publication. The final private release retains all four assets. The Pi then mirrors it using `/home/pi/ci-release-vault/tools/sync_private_release.py` under `~/ci-artifacts/private-releases/<tag>/`, with private permissions and durable filesystem operations.

Private publishing is **idempotent**. If an upload is interrupted, a retry
checks the existing draft, accepts only matching SHA-256 assets, uploads only
missing files, and refuses to overwrite or publish a tampered/partial release.
Transient GitHub API failures are retried a limited number of times while the
Pi still holds its one-time private key. If the process dies beforehand, rerun
the public synthetic CI rather than trying to recover an erased key.

The private Release is the canonical published output and is **not deleted** after download. The Pi keeps its own local copy indefinitely. GitHub job logs and workflow history may remain on the public repo, but they are *not* Actions artifacts.

## Verified public integration

A full encrypted public Windows/Linux run, Pi decryption, private GitHub Release publication, and durable Pi mirror passed in [public test run 38454705459](https://github.com/SUAS-STEM/ci-relay-lab/actions/runs/38454705459). The corresponding [private test release](https://github.com/SUAS-STEM/ci-release-vault/releases/tag/ci-public-test-38454705459-1) contains the two real synthetic executables plus checksum files. The public and private repositories reported **zero Actions artifacts**.

The above run was a **one-time feature-branch proof**. Its temporary push-triggered workflow was removed after the test, and the production version of `fixture.yml` remains manual/dispatch-only on protected `main`. A successful feature-branch proof does not mean the new workflow has been deployed to `main`: independent PR review and merge are still required. The retired workflow on `main` remains disabled until the replacement has been approved.

## Security boundaries and limitations

### Experimental related-project encrypted Windows/MSVC relay

`secure-opaque-build.yml` is a **separate** protocol: a lightweight private
coordinator dispatches this PUBLIC repository's Windows/MSVC runner to compile
an encrypted source bundle and private PowerShell build script. The worker
generates a one-time age keypair and publishes only its PUBLIC recipient;
the public worker also requests a short-lived GitHub-signed OIDC token whose
audience binds the one-time encryption recipients, nonce and private commit.
Before encrypting any private source, the coordinator verifies the real JWT
signature, issuer, exact public workflow/run/commit and token freshness. This
prevents an attacker with access to the temporary Release from simply
substituting their own recipient key. The public runner and its operators
remain inside the trust boundary.

The coordinator encrypts the source and `.ps1` to that recipient inside a
short-lived PUBLIC prerelease containing only ciphertext. The Windows runner
decrypts and compiles inside its temporary workspace, captures **the unchanged
combined compiler stdout/stderr byte stream**, and returns that log, a
separately authenticated status/hash, and the compiled `.exe`, all encrypted
to a separate one-time PRIVATE-side recipient. The private coordinator
now also requires a **second GitHub-signed OIDC proof** bound to the exact
return-log digest, executable digest, and Windows process exit code. Public
Release asset substitution cannot fabricate a correctly signed result without
control of the approved GitHub workflow execution. Compiler output is spooled
to a private temporary file with a size cap, including diagnostics on timeouts;
encrypted input downloads are checked against the GitHub asset digest before
being accepted. These protections passed the later live build described below.
The private coordinator validates and decrypts the results, publishes the actual binary, private
build log, checksum, and provenance into a PRIVATE Release, and deletes the
temporary PUBLIC ciphertext prerelease. **Zero Actions artifacts are used.**

The private coordinator first creates one exact ZIP containing a fresh 256-bit
secret commitment salt, then dispatches the **SHA-256 of that salted ZIP** as
public metadata. The public worker compares the hash of the decrypted ZIP
before unpacking or executing anything. This prevents an untrusted public
Release asset writer from substituting different source or PowerShell inputs
that merely reuse the published nonce and private commit SHA. The salt is
inside the encrypted ZIP, not an Actions workflow input. This protection is
only as strong as the reviewed workflow and its runner execution.

The real public `windows-2022` MSVC run
[38493277635](https://github.com/SUAS-STEM/ci-relay-lab/actions/runs/38493277635)
succeeded using **only synthetic** source and `.ps1` from the isolated private
[staging repository](https://github.com/SUAS-STEM/ci-private-build-lab). The
return output is in [PRIVATE Release `opaque-ci-38493277635`](https://github.com/SUAS-STEM/ci-private-build-lab/releases/tag/opaque-ci-38493277635).
This newer proof also checked the **salted archive hash before unpacking**,
authenticated both the input key and result hashes using GitHub-signed OIDC,
and confirmed the private MSVC diagnostics were returned byte-for-byte.
The public job logs were checked for private synthetic markers and executable
paths (neither appeared); its Actions artifact inventory was zero. The Pi
verified the private Release and saved an owner-only archive. The short-lived
public prerelease and one-time branch test workflow were removed afterward.

### Automatic cleanup after coordinator interruptions

The private coordinator normally deletes its temporary public encrypted
prerelease after verifying the private Release. If the coordinator or Pi
crashes, `.github/workflows/opaque-prerelease-cleanup.yml` runs **once daily**
on the reviewed public `main` branch and deletes only its own encrypted
prereleases older than 24 hours, after checking that no matching public runner
is still active. It validates the public repository's immutable numeric ID,
exact tag/notes, expected ciphertext-only filenames, SHA-256 asset metadata,
and a repeat Release snapshot immediately before deletion. Any unexpected
content or changed metadata fails closed rather than deleting unrelated
Releases. No private token or private repository is accessed. The public
workflow has not yet been merged/enabled; it will use a small amount of
PUBLIC Linux Actions time (roughly one billed minute per day, subject to
actual runtime). The separately prepared Pi cleanup timer remains disabled
until an appropriately scoped credential is installed.

This successful test used the Pi as the private-side coordinator; **private
GitHub-hosted Actions billing still blocks a complete private Actions test**.
The permanent PUBLIC dispatch workflow is still on an unmerged, independently
reviewed PR and is not enabled on protected `main`. No GCS repository code was
accessed, forwarded, or changed.

**Threat-model limit:** Encryption protects the contents from ordinary public
observers, but not from the GitHub/Microsoft runner infrastructure or an
attacker who controls its workflow/runtime. The public job's workflow source,
run metadata, one-time public keys, and encrypted temporary assets are visible.
The worker's release-upload token has write access **only to its public repo**,
not the private source or private output repository.

### Drop-in private-source build workflow (separate from this public test)

A **private** repository can call the *publicly readable workflow definition*
`.github/workflows/private-reusable-build.yml` using GitHub reusable workflows.
**Crucially, the jobs then execute in the PRIVATE caller's Actions context**:
the caller's private checkout, job logs, runner billing, and `GITHUB_TOKEN`.
The public `ci-relay-lab` workflow does not receive the caller's source or
logs. This does **not** provide public-repository/free-runner billing for
confidential source; attempts to transfer plaintext private builds into the
public test repo are not supported.

For a private CMake project, add a single caller workflow file, for example:

```yaml
name: Private compiled releases
on:
  workflow_dispatch:
  # Once private Actions billing/runner access is ready, optionally add:
  # push:
  #   branches: [main]
  #   paths: ['**/*.cpp', '**/*.h', '**/*.hpp', 'CMakeLists.txt', 'cmake/**', '.github/workflows/private-ci.yml']
permissions:
  contents: write
jobs:
  build:
    uses: SUAS-STEM/ci-relay-lab/.github/workflows/private-reusable-build.yml@REVIEWED_IMMUTABLE_COMMIT_SHA
    with:
      linux_binary: build/myprogram
      windows_binary: build/Release/myprogram.exe
```

Replace `REVIEWED_IMMUTABLE_COMMIT_SHA` with the reviewed workflow's **full
40-character commit SHA**, not a mutable branch or tag. Adjust the two binary
paths to match your CMake targets. Default publication is **directly into a
GitHub Release on that same private caller repo**, with no additional secrets
or Actions artifact uploads. Set `release_repository` to a different PRIVATE
repository (e.g. `SUAS-STEM/ci-release-vault`) only when you also explicitly
pass `vault_release_token` using a GitHub App or fine-grained, **vault-only**
`contents:write` credential. Never use a broad personal token in runners.

The reusable workflow also accepts `linux_runner` / `windows_runner` inputs
for approved trusted self-hosted runners. No such runner is registered for the
isolated sample today. The separate private sample repository
`SUAS-STEM/ci-private-build-lab` demonstrates the caller without touching GCS.

**Status:** This private-caller workflow is a staging integration with static
security checks and local build checks; it has **not** passed a hosted private
Actions run. GitHub's private-repository runner billing currently blocks jobs.
Do not represent a publicly defined workflow as a confidential-computing
enclave: hosted/private or self-hosted runners can see source plaintext while
compiling. Strict source confidentiality requires a runner you trust, protected
private workflows, narrow credentials, and appropriate network controls.

- **This is not a mechanism to compile proprietary GCS source in public Actions.** Encrypting output or encrypting a source archive cannot keep the source secret from a runner that executes it. Public runners see this repository's harmless pinned C++ toy source only. Private GCS needs a trusted private build environment.
- The one-time age *private* key stays on the Pi in anonymous memory. If the Pi crashes before fetching/decrypting, the job must be rerun with a fresh key; it is not recoverable from GitHub.
- A public ciphertext record can be seen by anybody with access to the public workflow logs. The one-time secret key remains private to the Pi. Once plaintext executables are published in a **private** Release, any authorized member of that private repo can download them.
- The Pi's `gh` credential is used to publish privately. **Never place its personal token on a public runner or in workflow inputs.** Use a short-lived, repository-scoped publishing identity before production automation.
- SHA-256, GitHub job identity checks, and age authentication are not the same as durable independent source provenance. For high-assurance use, add signed attestations and preserve verification evidence with releases.
- Pi at-rest storage is not encrypted. Set up an encrypted storage volume before using confidential release contents. Back up any important private releases independently.
- The fixed public fixture never reads, clones, or forwards a private repository. The public-source safety gate and pinned toy-source hashes reject accidental additional code.

## Tests

```sh
python3 tools/install_age.py
python3 -m unittest discover -s tests -q
python3 -m tools.public_guard --tree-only
```

The required PR check runs the Python security tests on Linux. The actual encrypted Windows/Linux build and Pi-to-private-Release integration has separately been tested end to end.

For private release verification, checksum readback, and long-term Pi mirroring, see `SUAS-STEM/ci-release-vault`. That repository also contains a separate, **currently billing-blocked**, private-hosted synthetic build demo which is not used by this public CI relay.
