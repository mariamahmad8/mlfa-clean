"""Backfill encrypted queue payloads without exposing message content in logs."""

import argparse
import json
import os
import sys
from pathlib import Path


V2_ROOT = Path(__file__).resolve().parents[1]
if str(V2_ROOT) not in sys.path:
    sys.path.insert(0, str(V2_ROOT))

from dotenv import load_dotenv
from sqlalchemy import text

load_dotenv()

from adapters.db import get_db_session
from security_encryption import decrypt_payload, encrypt_payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--clear-plaintext", action="store_true")
    parser.add_argument("--confirm-clear-plaintext", action="store_true")
    args = parser.parse_args()

    if args.clear_plaintext and not args.confirm_clear_plaintext:
        parser.error("--clear-plaintext requires --confirm-clear-plaintext")

    session = get_db_session()
    try:
        rows = session.execute(
            text("SELECT * FROM pending_queue ORDER BY id FOR UPDATE")
        ).mappings().all()
        encrypted_count = 0
        verified_count = 0

        for raw_row in rows:
            row = dict(raw_row)
            ciphertext = row.get("sensitive_payload_ciphertext")
            version = row.get("encryption_key_version")

            if not ciphertext:
                payload = {
                    "subject": row.get("subject_email") or "",
                    "body": row.get("body_email") or "",
                    "sender": row.get("sender") or "",
                    "classification": row.get("classification") or {},
                }
                ciphertext, version = encrypt_payload(payload)
                encrypted_count += 1
                if not args.dry_run:
                    session.execute(
                        text(
                            """
                            UPDATE pending_queue
                            SET sensitive_payload_ciphertext = :ciphertext,
                                encryption_key_version = :version
                            WHERE id = :id
                            """
                        ),
                        {"ciphertext": ciphertext, "version": version, "id": row["id"]},
                    )

            # A successful round trip proves that the configured versioned key
            # can recover every row before plaintext is cleared.
            recovered = decrypt_payload(ciphertext, int(version))
            if not isinstance(recovered.get("classification", {}), dict):
                raise RuntimeError(f"Queue row {row['id']} failed verification.")
            verified_count += 1

        if args.clear_plaintext and not args.dry_run:
            session.execute(
                text(
                    """
                    UPDATE pending_queue
                    SET subject_email = '', body_email = '', sender = '',
                        classification = '{}'::jsonb
                    WHERE sensitive_payload_ciphertext IS NOT NULL
                      AND encryption_key_version IS NOT NULL
                    """
                )
            )

        if args.dry_run:
            session.rollback()
        else:
            session.commit()

        print(
            json.dumps(
                {
                    "rows": len(rows),
                    "newly_encrypted": encrypted_count,
                    "verified": verified_count,
                    "plaintext_cleared": bool(args.clear_plaintext and not args.dry_run),
                    "dry_run": args.dry_run,
                },
                sort_keys=True,
            )
        )
        return 0
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
