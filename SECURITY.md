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

- The built-in public `GITHUB_TOKEN` has read-only permission, and no Pi token or release-writer permission is available to public runners. The private-release writer remains on the Pi. A dedicated repository-scoped GitHub App token should replace the Pi's broad personal token for unattended production operation.
- Source confidentiality cannot be achieved if proprietary GCS code is built on a public GitHub-hosted runner, even if GitHub Release publication is private. Use a trusted private execution environment for such builds.
- Ciphertext transport in **public** workflow logs means those encrypted bytes may be retained under GitHub's log-retention policy. No Actions artifacts are created; GitHub run logs are a separate storage class.
- If the Pi or dispatcher dies before decrypting a run, its one-time age identity is lost. Rerun CI with a new key; ciphertext logs alone cannot restore the key.
- Encryption and SHA-256 detect ciphertext corruption but do **not independently attest runner honesty**. The GitHub-run/job identity and pinned toy source provide context. Future confidential build systems should use signed provenance with a durable offline-verifiable trust root.
- The private repository's exact-release verifier checks tag, source run/commit, workflow, job outcome, asset count and SHA-256. GitHub administrators with sufficient write access can still mutate tags and releases; plan for immutable external signed attestations.
- The Pi archive currently has Unix file permissions, not disk-level encryption or an independent offsite backup. A stolen SSD or compromised privileged account can expose its plaintext private-release assets.
- The public fixture contains a deliberately generated, random synthetic canary to test accidental plaintext logging; it does not use proprietary secrets.

## Source and release review

The approved public CI workflow is manual, `main`-only, and restricted to the approved actor. The repository's protected `main` requires an independent reviewer and the `public-source-gate` check. The one-off temporary integration workflow used during the live proof has been removed; do not re-enable it.

The previous artifact-ZIP upload and signer job were **retired** in favor of ciphertext-in-job-log transport plus Pi-controlled private Releases. Do not assume Sigstore attestations from the retired workflow apply to the new mechanism. Separate signed provenance remains future work.
