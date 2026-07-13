-- Prevent two category rules with the same key on the same inbox.
-- (E.g. can't have two "donor" rules on the MLFA inbox.)

CREATE UNIQUE INDEX IF NOT EXISTS category_rules_unique_key_per_inbox
    ON category_rules (inbox_id, key_for_category);
