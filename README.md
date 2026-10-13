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
