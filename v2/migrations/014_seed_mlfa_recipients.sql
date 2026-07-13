-- Seed MLFA recipients from the existing category_rules.emails_to_forward.
-- These are the staff addresses referenced by the seeded MLFA rules.

INSERT INTO recipients (inbox_id, label_recipient, email, notes, active) VALUES
(1, 'Maria Laura', 'Maria.laura@mlfa.org', 'Violation notice routing', true),
(1, 'MLFA Giving Team', 'give@mlfa.org', 'Donor and grant forwarding', true),
(1, 'Maryam Libdi', 'maryam.libdi@mlfa.org', 'Volunteer and community engagement', true),
(1, 'Aisha Ukiu', 'aisha.ukiu@mlfa.org', 'Training & Development (law student internships)', true),
(1, 'Shawn (Strategic HR)', 'shawn@strategichradvisory.com', 'Job applications', true),
(1, 'MLFA Media', 'media@mlfa.org', 'Media inquiries', true),
(1, 'Syeda Sadiqa', 'Syeda.sadiqa@mlfa.org', 'Invoices (>= $1,000)', true);
