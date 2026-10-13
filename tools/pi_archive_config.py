"""Enable fail-closed offline-recipient encryption for all future Pi archives.

The recovery PRIVATE key MUST be generated and retained outside the Pi.
This command only reads the public recipient file; it never accepts secrets.
"""

import argparse

try:
    from .pi_artifact_store import (ARCHIVE_RECIPIENT_FILE,
                                     configured_archive_recipient,
                                     require_archive_encryption)
except ImportError:
    from pi_artifact_store import (ARCHIVE_RECIPIENT_FILE,
                                   configured_archive_recipient,
                                   require_archive_encryption)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-encryption", action="store_true",
                        help="Forbid all future plaintext Pi CI archives")
    args = parser.parse_args()
    if not args.require_encryption:
        parser.error("Pass --require-encryption to explicitly enable the policy")
    require_archive_encryption()
    if configured_archive_recipient() is None:
        raise RuntimeError("Offline recipient verification failed")
    print("Offline-recipient encryption required for future Pi CI archives")
    print("Recovery private key must remain off this Pi")
    print("Public recipient file: " + str(ARCHIVE_RECIPIENT_FILE))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
