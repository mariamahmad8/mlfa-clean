INSERT INTO inboxes (email_to_watch, display_name, automation_mode, blocked_senders, skip_sender_pairs)
VALUES (
    'info@mlfa.org',
    'MLFA Info Inbox',
    false,
    '["abesammour@yahoo.com", "info@mlfa.org"]'::jsonb,
    '[["info@mlfa.org", "mariam.ahmad@pairsys.ai"]]'::jsonb
);
