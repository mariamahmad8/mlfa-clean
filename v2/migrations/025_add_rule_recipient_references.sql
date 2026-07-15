-- Normalize category forwarding recipients while retaining
-- category_rules.emails_to_forward as a rollback/legacy fallback.

-- Composite keys let PostgreSQL enforce that a rule can only reference a
-- recipient from the same inbox, rather than relying on UI validation alone.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_category_rules_id_inbox'
    ) THEN
        ALTER TABLE category_rules
            ADD CONSTRAINT uq_category_rules_id_inbox UNIQUE (id, inbox_id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_recipients_id_inbox'
    ) THEN
        ALTER TABLE recipients
            ADD CONSTRAINT uq_recipients_id_inbox UNIQUE (id, inbox_id);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS category_rule_recipients (
    category_rule_id INTEGER NOT NULL
        REFERENCES category_rules(id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL
        REFERENCES recipients(id) ON DELETE RESTRICT,
    inbox_id INTEGER NOT NULL REFERENCES inboxes(id) ON DELETE CASCADE,
    FOREIGN KEY (category_rule_id, inbox_id)
        REFERENCES category_rules(id, inbox_id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id, inbox_id)
        REFERENCES recipients(id, inbox_id) ON DELETE RESTRICT,
    PRIMARY KEY (category_rule_id, recipient_id)
);

CREATE INDEX IF NOT EXISTS idx_category_rule_recipients_recipient_id
    ON category_rule_recipients(recipient_id);

ALTER TABLE category_rules
    ADD COLUMN IF NOT EXISTS recipient_links_migrated BOOLEAN NOT NULL DEFAULT false;

-- Link only addresses that have exactly one matching directory recipient in
-- the same inbox. Ambiguous or missing addresses remain on the legacy path.
WITH email_matches AS (
    SELECT
        cr.id AS rule_id,
        address.value AS email,
        MIN(r.id) AS recipient_id,
        COUNT(r.id) AS match_count
    FROM category_rules cr
    CROSS JOIN LATERAL jsonb_array_elements_text(
        COALESCE(cr.emails_to_forward, '[]'::jsonb)
    ) AS address(value)
    LEFT JOIN recipients r
      ON r.inbox_id = cr.inbox_id
     AND LOWER(r.email) = LOWER(address.value)
    GROUP BY cr.id, address.value
)
INSERT INTO category_rule_recipients (category_rule_id, recipient_id, inbox_id)
SELECT matches.rule_id, matches.recipient_id, cr.inbox_id
FROM email_matches matches
JOIN category_rules cr ON cr.id = matches.rule_id
WHERE match_count = 1
ON CONFLICT DO NOTHING;

-- A rule switches to ID-based resolution only when every legacy address was
-- mapped unambiguously. Empty recipient lists are safe to mark migrated.
WITH email_matches AS (
    SELECT
        cr.id AS rule_id,
        address.value AS email,
        COUNT(r.id) AS match_count
    FROM category_rules cr
    CROSS JOIN LATERAL jsonb_array_elements_text(
        COALESCE(cr.emails_to_forward, '[]'::jsonb)
    ) AS address(value)
    LEFT JOIN recipients r
      ON r.inbox_id = cr.inbox_id
     AND LOWER(r.email) = LOWER(address.value)
    GROUP BY cr.id, address.value
)
UPDATE category_rules cr
SET recipient_links_migrated = true
WHERE NOT EXISTS (
    SELECT 1
    FROM email_matches matches
    WHERE matches.rule_id = cr.id
      AND matches.match_count <> 1
);
