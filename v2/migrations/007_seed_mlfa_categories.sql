-- Seed MLFA's category rules verbatim from the original classify_email prompt.
-- One INSERT per category to avoid DBeaver parser splitting on blank lines.

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'jail_mail', 'Jail Mail', $$JAIL MAIL

Categorize as "jail_mail" ONLY IF the CURRENT message:
- explicitly references incarceration (prison, jail, ICE custody, federal custody, CorrLinks, inmate messaging), AND
- contains a NEW, explicit, present-tense request for legal help, representation, or intervention

OR:
- is a system-generated inmate/jail communication (e.g., CorrLinks notification)

DO NOT classify as "jail_mail" if:
- the message is a follow-up, status check, acknowledgment, or continuation of a prior request
- the message references detention but does NOT make a new request for help

→ In those cases, classify as "active_communication"

IMPORTANT:
- Determine "jail_mail" using ONLY the current message (ignore prior thread context)$$, true, false, true, '[]'::jsonb, 'Apply for help/Jail_Mail', $$<p>{{greeting}}</p>
<p>Thank you for contacting the Muslim Legal Fund of America (MLFA).</p>
<p>If you have not already done so, please submit a formal application for legal assistance through our website:<br>
<a href="https://mlfa.org/application-for-legal-assistance/">https://mlfa.org/application-for-legal-assistance/</a></p>
<p>This ensures our legal team has the information needed to review your case promptly.</p>
<p>If you have already submitted an application, please disregard this request; no further action is needed at this time.</p>
<p>Sincerely,<br>The MLFA Team</p>$$, NULL, 1, true, true);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'legal', 'Legal Inquiry', $$LEGAL INQUIRIES

Classify as "legal" ONLY IF the CURRENT message contains a clear, explicit, present-tense request for legal help or representation.

Examples:
- asking for a lawyer
- requesting legal assistance
- describing a case and asking MLFA for help

DO NOT classify as "legal" if:
- the message is a follow-up or status check on a prior request
- the sender references a prior application or outreach
- the message expresses gratitude only
- the message mentions a legal issue but does NOT request help

If the sender references existing representation, ongoing coordination, or prior engagement with MLFA, classify as "active_communication" even if legal issues are described.

→ In these cases, classify as "active_communication"

KEY RULE:
- "legal" = NEW request for help
- follow-ups or ongoing conversations = "active_communication"

--- ADDITIONAL CLARIFICATIONS ---

DO NOT classify as "legal" if the email is a **legal notice**, **copyright or DMCA complaint**, **policy violation alert**, or **cease and desist letter** directed *at* MLFA.
These messages are fundamentally different from help requests — they are **enforcement or warning communications**, not assistance-seeking emails.

Common examples that should NOT be tagged as "legal":
- Copyright infringement notices (e.g., from law firms or record labels).
- DMCA or IP violation notifications.
- Cease-and-desist or trademark enforcement emails.
- Terms-of-service or content removal warnings from platforms like Meta, YouTube, or Google.
- Legal complaints, subpoenas, or compliance correspondence **sent to** MLFA (not *from* someone seeking MLFA's help).

Such messages must **never** trigger a "legal" classification or auto-response.

Remember:
- "Legal" = someone asking MLFA for help.
- "Violation notice" = someone legitimate warning MLFA about a potential violation.$$, true, false, true, '[]'::jsonb, 'Apply for help', $$<p>{{greeting}}</p>
<p>Thank you for contacting the Muslim Legal Fund of America (MLFA).</p>
<p>If you have not already done so, please submit a formal application for legal assistance through our website:<br>
<a href="https://mlfa.org/application-for-legal-assistance/">https://mlfa.org/application-for-legal-assistance/</a></p>
<p>This ensures our legal team has the information needed to review your case promptly.</p>
<p>If you have already submitted an application, please disregard this request; no further action is needed at this time.</p>
<p>Sincerely,<br>The MLFA Team</p>$$, NULL, 2, true, true);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'violation_notice', 'Violation Notice', $$Violation or Legal Notice emails → Categorize as "violation_notice" if the sender is **not requesting help**, but is **informing or warning MLFA** about an alleged violation or legal issue.

Examples include:
- "We represent [Company] regarding unauthorized use of copyrighted material…"
- "Your post infringes on our intellectual property rights."
- "Notice of policy breach or DMCA claim."

These emails are not client or community outreach — they are compliance or legal enforcement notices.
Forward all "violation_notice" emails to: Maria.laura@mlfa.org$$, true, false, false, '["Maria.laura@mlfa.org"]'::jsonb, 'Irrelevant/Violation_Notices', '', NULL, 3, true, false);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'grant', 'Grant', $$Grant tag → If the email references a pending grant, matching gift program, corporate grant disbursement, PayPal Giving Fund, or employer match, it must remain categorized as "donor" AND include an additional tag "grant" because these require time-sensitive processing.

For an email to have the "grant" tag it must also be tagged as "donor".

Grant, employer match, corporate giving, corporate grant disbursement, and PayPal Giving Fund emails must be tagged "donor" and "grant" and always forwarded to give@mlfa.org regardless of amount.$$, true, false, false, '["give@mlfa.org"]'::jsonb, 'Donor_Related/Grant', '', NULL, 4, true, false);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'donor', 'Donor', $$DONOR CLASSIFICATION + FORWARDING RULES

Categorize as "donor" if the email is from an individual donor or concerns a specific donation, payment, receipt, tax receipt, confirmation, donor follow-up, payment issue, employer match, corporate giving, PayPal Giving Fund, or grant disbursement.

Do NOT categorize as "donor" if the sender is asking MLFA for money, funding, sponsorship, or financial support. Use "sponsorship" or "financial_aid" instead.

FORWARDING:
- Forward active donor communications to give@mlfa.org regardless of amount, including questions, receipt requests, payment issues, follow-ups, or references to a prior donation.
- Do not forward passive automated donation/payment notifications under $1,000 if they merely report that someone donated or that a payment was received.
- Forward passive automated donation/payment notifications only if the final donation/payment amount is ≥ $1,000.
- Grant, employer match, corporate giving, corporate grant disbursement, and PayPal Giving Fund emails must be tagged "donor" and "grant" and always forwarded to give@mlfa.org.

AMOUNT RULE:
Extract only the final donation/payment amount as amount_detected. Ignore pledges, goals, years, IDs, balances, or unrelated numbers.$$, false, false, false, '["give@mlfa.org"]'::jsonb, 'Donor_Related', '', 1000, 5, true, false);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'sponsorship', 'Sponsorship', $$Sponsorship requests → If someone is **requesting sponsorship, fundraiser, from MLFA**, categorize as "sponsorship".
Leave recipients as blank.$$, true, false, false, '[]'::jsonb, 'Sponsorship', '', NULL, 6, true, false);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'organizational', 'Organizational Inquiry', $$Organizational questions → If the sender is asking about **MLFA's internal operations**, such as leadership, partnerships, collaboration, or continuing an ongoing, **legitimate and relevant exchange** with MLFA, categorize as "organizational".

This includes **genuine follow-up emails** that relate to a prior valid conversation with MLFA (e.g., "Following up on my partnership proposal," or "Checking in about our meeting last week").

The model must use the **context provided** — including quoted or prior messages — to assess whether the follow-up continues a **legitimate and relevant** thread. This means that if prior emails are available (as part of the thread context), they must be analyzed to decide if the new message is a meaningful continuation or just noise.

**Not all follow-ups qualify:**
- If the previous thread or earlier messages were categorized as "cold_outreach", "auto_reply", "irrelevant_other", **or any test, placeholder, or nonsense content**, then a follow-up on that thread should **not** be marked as "organizational".
- In such cases, classify based on the *current message's actual content or purpose* (e.g., "irrelevant_other" if still meaningless).
- A message like "Just following up on my last email" **only counts as organizational** if the last email was legitimate and relevant to MLFA's work.

Forward to: Nobody/No recipients.$$, false, false, false, '[]'::jsonb, 'Organizational_Inquiries', '', NULL, 7, true, false);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'volunteer', 'Volunteer', $$Volunteer inquiries → If someone is **offering to volunteer** their time or skills to MLFA **or** is **asking about volunteering** (for themselves or on behalf of someone else), categorize as "volunteer". Forward to: maryam.libdi@mlfa.org$$, true, false, true, '["maryam.libdi@mlfa.org"]'::jsonb, 'Volunteer', $$<p>{{greeting}}</p>
<p>Thank you for your interest in volunteering with the Muslim Legal Fund of America (MLFA). We sincerely appreciate your willingness to support our mission.</p>
<p>If you would like to get involved, please complete our Volunteer Interest Form here:<br>
<a href="https://mlfa.org/join-our-team/">MLFA Volunteer Form</a></p>
<p>Our Community Engagement team will review your submission and follow up as appropriate.</p>
<p>We look forward to connecting with you.</p>
<p>Sincerely,<br>The Muslim Legal Fund of America</p>$$, NULL, 8, true, true);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'internship_law_student', 'Internship (Law Student)', $$Internship applications → If someone is applying for an internship (paid or unpaid), sending a resume for an internship program, or inquiring about internship opportunities, categorize based on the sender's status:
- If the sender explicitly states they are a current law student (e.g., law school, JD, 1L/2L/3L, LLM), categorize as "internship_law_student".
- If the sender explicitly states they are an undergraduate, high school student, pre-law student, community college student, or any non-law student, categorize as "internship_undergraduate".
- If the sender does NOT specify whether they are a law student, default to "internship_undergraduate".

ONLY "internship_law_student" will be forwarded to: aisha.ukiu@mlfa.org
"internship_undergraduate" emails will NOT be forwarded to anyone.$$, false, false, true, '["aisha.ukiu@mlfa.org"]'::jsonb, 'Internship', $$<p>{{greeting}}</p>
<p>Thank you for reaching out and for your interest in interning with the Muslim Legal Fund of America (MLFA).</p>
<p>Our internship program is open to current law students, and we welcome applications from those who are passionate about constitutional rights and public interest advocacy.</p>
<p>To be considered, please submit your cover letter, résumé, and writing sample directly to our Training and Development Manager at <a href="mailto:aisha.ukiu@mlfa.org">aisha.ukiu@mlfa.org</a> and copy <a href="mailto:maryam.libdi@mlfa.org">maryam.libdi@mlfa.org</a> on your email.</p>
<p>Once we receive your submission, a member of our team will review your application and follow up regarding next steps.</p>
<p>We are grateful for your interest in MLFA and look forward to connecting.</p>
<p>Warm regards,<br>The Muslim Legal Fund of America.</p>$$, NULL, 9, true, true);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'internship_undergraduate', 'Internship (Undergraduate)', $$Internship applications → If someone is applying for an internship (paid or unpaid), sending a resume for an internship program, or inquiring about internship opportunities, categorize based on the sender's status:
- If the sender explicitly states they are a current law student (e.g., law school, JD, 1L/2L/3L, LLM), categorize as "internship_law_student".
- If the sender explicitly states they are an undergraduate, high school student, pre-law student, community college student, or any non-law student, categorize as "internship_undergraduate".
- If the sender does NOT specify whether they are a law student, default to "internship_undergraduate".

ONLY "internship_law_student" will be forwarded to: aisha.ukiu@mlfa.org
"internship_undergraduate" emails will NOT be forwarded to anyone.$$, false, false, true, '[]'::jsonb, 'Internship', $$<p>{{greeting}}</p>
<p>Thank you for your interest in the Muslim Legal Fund of America (MLFA). We appreciate your enthusiasm and desire to support our work.</p>
<p>At this time, MLFA's internship program is open exclusively to current law students. We are unable to offer internship placements to undergraduate and high school students.</p>
<p>That said, we welcome undergraduate students to get involved through our volunteer program. If you are interested in supporting our mission through volunteer efforts, please complete our volunteer form.</p>
<p>Our team will review your submission and follow up as appropriate.</p>
<p>We're grateful for your interest in MLFA and encourage you to stay connected as you continue your academic and professional journey.</p>
<p>Sincerely,<br>The Muslim Legal Fund of America</p>$$, NULL, 10, true, true);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'job_application', 'Job Application', $$Job applications → If someone is **applying for a paid job**, sending a resume, or asking about open employment positions, categorize as "job_application". Forward to: shawn@strategichradvisory.com$$, true, false, false, '["shawn@strategichradvisory.com"]'::jsonb, 'Job_Application', '', NULL, 11, true, false);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'media', 'Media Inquiry', $$Media inquiries → classify as "media" ONLY if the sender explicitly requests an interview, statement, comment, or coverage involving MLFA.

Do NOT classify as "media" if:
- the sender is only sharing content or links
- the message is not tailored to MLFA
- there is no request directed at MLFA

→ classify as "cold_outreach" or "irrelevant_other"

Forward all "media" emails to: media@mlfa.org$$, true, false, false, '["media@mlfa.org"]'::jsonb, 'Media', '', NULL, 12, true, false);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'invoice', 'Invoice', $$INVOICE:
Tag "invoice" if payment is being requested (amount owed, due date, invoice label).

Forwarding:
- ≥ $1,000 → forward to: Syeda.sadiqa@mlfa.org
- < $1,000 → do NOT forward

Amount:
- Use final total; if unclear → do NOT forward
Also return:
- amount_detected: number or null$$, true, false, false, '["Syeda.sadiqa@mlfa.org"]'::jsonb, 'Invoices', '', 1000, 13, true, false);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'statements_receipts', 'Statements / Receipts', $$STATEMENTS / RECEIPTS:
Tag "statements_receipts" if it includes payment confirmation or receipt details (amount, tax, total, billing summary).

Includes:
- Order confirmations WITH pricing

Exclude:
- Order confirmations WITHOUT pricing
- Shipping / tracking updates
- Promotions
- Automated system notifications (unless human inquiry)

Forwarding:
- Do NOT forward$$, true, false, false, '[]'::jsonb, 'Statements', '', NULL, 14, true, false);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'financial_aid', 'Financial Aid Request', $$Financial_Aid → if someone is requesting ANY sort of financial support, it is NOT sponsorship, rather it is categorized as "financial_aid".$$, true, false, true, '[]'::jsonb, 'Financial_Assistance', $$<p>Assalamu alaikum,</p>
<p>Thank you for reaching out to the Muslim Legal Fund of America (MLFA).</p>
<p>We would like to clarify that our organization does not provide direct personal financial assistance. Rather, MLFA supports and funds legal representation in select cases that impact the civil liberties and constitutional rights of Muslims in America. For this reason, we are not able to offer the type of financial assistance you are requesting.</p>
<p>If you have a legal matter that you would like us to consider, you may complete an official inquiry for our attorneys to review: <a href="https://mlfa.org/application-for-legal-assistance/">Application for Legal Assistance - MLFA</a></p>
<p>We sincerely hope that you are able to find the resources and support you need, and we pray for ease and better days ahead.</p>
<p>Sincerely,<br>The Muslim Legal Fund of America</p>$$, NULL, 15, true, true);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'active_communication', 'Active Communication', $$Active communications → Categorize as "active_communication" for legitimate, non-spam email threads or replies that do not fit any other defined category but are still relevant and meaningful to MLFA.

This category exists to ensure valid conversations are not misclassified as "irrelevant_other".

Use "active_communication" when the email:
- Contains attachments or phrases like "please let me know if you receive this," suggesting an ongoing exchange, even if not in a visible thread
- Does not meet the criteria for any other category, AND
- Is clearly directed to a specific individual or team within the organization (e.g., uses a real name or role-based greeting), indicating it is part of an ongoing or intended conversation
- Is coherent, not cold outreach, and serves a legitimate conversational or administrative purpose (e.g., clarifications, acknowledgments, coordination, brief responses, logistics)

Do NOT use "active_communication" for:
- cold outreach
- automated messages
- test emails
- content with no meaningful purpose

If none of the above apply, classify as "irrelevant_other"$$, false, false, false, '[]'::jsonb, 'Active_Communication', '', NULL, 16, true, false);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'cold_outreach', 'Cold Outreach', $$Cold outreach → Any **unsolicited sales email** that lacks clear tailoring to MLFA's work. Categorize as "cold_outreach" if:
- The sender shows **no meaningful awareness** of MLFA's mission
- The offer is **broad, mass-marketed, or hype-driven**
- The email uses commercial hooks like "Act now," "800% increase," "Only $99/month," or "Click here"

Even if the topic sounds legal or nonprofit-adjacent, if it **feels generic**, classify it as cold outreach.

**IMPORTANT: Do NOT classify follow-up emails as cold outreach**
Mark as read;
Bulk content like PR updates, blog digests, or mass announcements not addressed to MLFA directly.
If the email contains the word "UNSUBSCRIBE" anywhere in the body, it MUST be categorized as "cold_outreach" regardless of other content. There can be a few exceptions to that rule for example it might be from an organization that is asking for a donation/fundraising which would then be sponsorship.

EXCLUSIVITY RULE:
If an email is classified as "cold_outreach", it may NOT be assigned any additional categories.
Cold outreach must always be the ONLY category.$$, true, false, false, '[]'::jsonb, 'Irrelevant/Cold_Outreach', '', NULL, 17, true, false);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'irrelevant_other', 'Irrelevant (Other)', $$Irrelevant (other) → Anything that doesn't match the above and is unrelated to MLFA's mission
- Obvious scams, spam, phishing, AI-generated nonsense, or malicious intent.
— e.g., misdirected emails, general inquiries, or off-topic messages. Mark as read and ignore.$$, true, false, false, '[]'::jsonb, 'Irrelevant/Other', '', NULL, 18, true, false);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'auto_reply', 'Auto Reply', $$Automatic replies (including out-of-office) → Categorize as "auto_reply" if the email is an automatically generated response triggered by our outbound message. This includes:
1) Traditional out-of-office notices (e.g., "I am out of the office until...", "I will return on...", "I have limited access to email...")
2) Emails explicitly labeled "Automatic reply", "Out of Office", "Auto-Reply", "OOO", "Away from office"
3) Institutional auto-acknowledgments (e.g., "Your message has been received", "Someone will get back to you as soon as possible", "Thank you for contacting us")

These should NOT be forwarded and should be moved to Trash.$$, true, false, false, '[]'::jsonb, 'Deleted Items', '', NULL, 19, true, false);

INSERT INTO category_rules (inbox_id, key_for_category, label, rule_text, mark_read, skip_email, auto_reply_safeguard, emails_to_forward, folder_path, reply_template, amount_threshold, priority, active, auto_reply_enabled) VALUES (1, 'delete_internal', 'Delete (Internal)', $$Microsoft Teams forwarded messages (delete) → Categorize as "delete_internal" if the email is a forwarded or auto-generated message originating from Microsoft Teams.

These emails are internal notification artifacts and provide no standalone communication value. They should be classified as "delete_internal" and deleted. They should not be forwarded, replied to, or categorized under any other label.$$, true, false, false, '[]'::jsonb, 'Deleted Items', '', NULL, 20, true, false);
