-- Link category rules to reusable templates while retaining the legacy text
-- columns as a deployment fallback. Apply this migration before deploying the
-- code that writes reply_template_id fields.

ALTER TABLE category_rules
    ADD COLUMN IF NOT EXISTS reply_template_id INTEGER
    REFERENCES reply_templates(id) ON DELETE RESTRICT;

ALTER TABLE category_rules
    ADD COLUMN IF NOT EXISTS reply_template_personal_id INTEGER
    REFERENCES reply_templates(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_category_rules_reply_template_id
    ON category_rules(reply_template_id);

CREATE INDEX IF NOT EXISTS idx_category_rules_reply_template_personal_id
    ON category_rules(reply_template_personal_id);

-- Backfill only exact, unambiguous matches within the same inbox. Drifted or
-- custom rule text remains unlinked and can be deliberately reselected in UI.
WITH matches AS (
    SELECT cr.id AS rule_id, MIN(rt.id) AS template_id
    FROM category_rules cr
    JOIN reply_templates rt
      ON rt.inbox_id = cr.inbox_id
     AND rt.body_html = cr.reply_template
    WHERE cr.reply_template_id IS NULL
      AND NULLIF(cr.reply_template, '') IS NOT NULL
    GROUP BY cr.id
    HAVING COUNT(*) = 1
)
UPDATE category_rules cr
SET reply_template_id = matches.template_id
FROM matches
WHERE cr.id = matches.rule_id;

WITH matches AS (
    SELECT cr.id AS rule_id, MIN(rt.id) AS template_id
    FROM category_rules cr
    JOIN reply_templates rt
      ON rt.inbox_id = cr.inbox_id
     AND rt.body_html = cr.reply_template_personal
    WHERE cr.reply_template_personal_id IS NULL
      AND NULLIF(cr.reply_template_personal, '') IS NOT NULL
    GROUP BY cr.id
    HAVING COUNT(*) = 1
)
UPDATE category_rules cr
SET reply_template_personal_id = matches.template_id
FROM matches
WHERE cr.id = matches.rule_id;

