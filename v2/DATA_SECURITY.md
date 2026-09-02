# Email Data Security and Operations

Application-level queue encryption is implemented. Microsoft 365 remains the
authoritative email store, and the encrypted PostgreSQL queue is the only place
where the Hub temporarily persists email bodies. The staged procedure below is
retained for deployment verification, recovery, and future environment setup.

## OpenAI governance gate

The active V2 OpenAI call explicitly sets `store=False`. OpenAI API data is not
used for training by default unless an organization opts in, but default abuse
monitoring may retain customer content for up to 30 days. Before production use
with legal or donor correspondence, MLFA must:

1. Approve OpenAI as a data subprocessor in writing.
2. Confirm API input/output sharing is disabled for the OpenAI organization and project.
3. Determine eligibility for Zero Data Retention or Modified Abuse Monitoring.
4. Record which inboxes are allowed to use AI.

Each inbox has `send_to_openai`. When disabled, the worker skips OpenAI and a
reviewer must select categories manually in the Hub.

Official data-control documentation:
https://platform.openai.com/docs/models/default-usage-policies-by-endpoint

## Encryption keys

Queue encryption uses Fernet authenticated encryption in the backend storage
layer. Keys are sealed Railway variables and are never sent to the browser.

Required variables for encrypted modes:

```text
QUEUE_ENCRYPTION_CURRENT_VERSION=1
QUEUE_ENCRYPTION_KEY_V1=<Fernet key>
```

Generate a key locally:

```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

For annual rotation, add `QUEUE_ENCRYPTION_KEY_V2`, change the current version
to `2`, and retain V1 until every V1 queue row has expired. If a key is lost,
temporary snapshots using it are unrecoverable; the original email remains in
Microsoft 365.

## Deployment sequence

1. Apply `migrations/026_secure_queue_foundation.sql`. It is additive and does
   not delete or transform existing rows.
2. Deploy with `QUEUE_SECURITY_MODE=legacy`.
3. Add and seal the V1 encryption key in Railway.
4. Verify the backfill without writing:

   ```bash
   python3 v2/scripts/encrypt_pending_queue.py --dry-run
   ```

5. Encrypt every existing row while retaining plaintext temporarily:

   ```bash
   python3 v2/scripts/encrypt_pending_queue.py
   ```

6. Set `QUEUE_SECURITY_MODE=encrypted_fallback` and redeploy. From this point,
   every new row is encrypted instead of written as plaintext.
7. Run the encryption command again to catch anything queued during the
   deployment, then run `--dry-run`. The `verified` count must equal `rows`.
8. Clear plaintext only after successful verification:

   ```bash
   python3 v2/scripts/encrypt_pending_queue.py \
     --clear-plaintext --confirm-clear-plaintext
   ```

9. The Hub now continues using the database, but sensitive queue payloads are encrypted.
10. After functional testing, set `QUEUE_SECURITY_MODE=microsoft_primary`.
   Queue lists use encrypted metadata; opening one email fetches its content
   live from Microsoft. If Graph is temporarily unavailable, the encrypted body
   is shown with a warning.
11. Observe the live-fetch path for at least one week.
12. Set `QUEUE_SECURITY_MODE=microsoft_only`. New queue rows retain encrypted
    subject, sender, and classification for workflow display, but not the body.
    Existing encrypted fallback bodies disappear as their per-inbox retention
    periods expire.

Do not jump directly from `legacy` to `microsoft_only`.

## Retention and missing messages

Retention is configured per inbox from 1 to 365 days. Expired Hub rows are
deleted while the Outlook source receives `PAIRActioned/queue_expired`. The
original email and any Microsoft legal-hold policy are unaffected.

In Microsoft-primary modes:

- Available message: display live Microsoft content.
- Microsoft temporarily unavailable: display encrypted fallback when present.
- Message missing and no fallback: show an unavailable state and disable approval.

Audit records intentionally retain opaque message IDs and actions after queue
content expires. They do not retain full email bodies.
