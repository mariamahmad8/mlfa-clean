-- Seed MLFA reply templates from the existing category_rules.reply_template values.
-- These correspond to the templates currently embedded in the category rules.

INSERT INTO reply_templates (inbox_id, name_template, body_html, active) VALUES
(1, 'Legal / Jail Mail default reply', $$<p>{{greeting}}</p>
<p>Thank you for contacting the Muslim Legal Fund of America (MLFA).</p>
<p>If you have not already done so, please submit a formal application for legal assistance through our website:<br>
<a href="https://mlfa.org/application-for-legal-assistance/">https://mlfa.org/application-for-legal-assistance/</a></p>
<p>This ensures our legal team has the information needed to review your case promptly.</p>
<p>If you have already submitted an application, please disregard this request; no further action is needed at this time.</p>
<p>Sincerely,<br>The MLFA Team</p>$$, true),

(1, 'Volunteer default reply', $$<p>{{greeting}}</p>
<p>Thank you for your interest in volunteering with the Muslim Legal Fund of America (MLFA). We sincerely appreciate your willingness to support our mission.</p>
<p>If you would like to get involved, please complete our Volunteer Interest Form here:<br>
<a href="https://mlfa.org/join-our-team/">MLFA Volunteer Form</a></p>
<p>Our Community Engagement team will review your submission and follow up as appropriate.</p>
<p>We look forward to connecting with you.</p>
<p>Sincerely,<br>The Muslim Legal Fund of America</p>$$, true),

(1, 'Internship (Law Student) reply', $$<p>{{greeting}}</p>
<p>Thank you for reaching out and for your interest in interning with the Muslim Legal Fund of America (MLFA).</p>
<p>Our internship program is open to current law students, and we welcome applications from those who are passionate about constitutional rights and public interest advocacy.</p>
<p>To be considered, please submit your cover letter, resume, and writing sample directly to our Training and Development Manager at <a href="mailto:aisha.ukiu@mlfa.org">aisha.ukiu@mlfa.org</a> and copy <a href="mailto:maryam.libdi@mlfa.org">maryam.libdi@mlfa.org</a> on your email.</p>
<p>Once we receive your submission, a member of our team will review your application and follow up regarding next steps.</p>
<p>We are grateful for your interest in MLFA and look forward to connecting.</p>
<p>Warm regards,<br>The Muslim Legal Fund of America.</p>$$, true),

(1, 'Internship (Undergraduate) reply', $$<p>{{greeting}}</p>
<p>Thank you for your interest in the Muslim Legal Fund of America (MLFA). We appreciate your enthusiasm and desire to support our work.</p>
<p>At this time, MLFA's internship program is open exclusively to current law students. We are unable to offer internship placements to undergraduate and high school students.</p>
<p>That said, we welcome undergraduate students to get involved through our volunteer program. If you are interested in supporting our mission through volunteer efforts, please complete our volunteer form.</p>
<p>Our team will review your submission and follow up as appropriate.</p>
<p>We're grateful for your interest in MLFA and encourage you to stay connected as you continue your academic and professional journey.</p>
<p>Sincerely,<br>The Muslim Legal Fund of America</p>$$, true),

(1, 'Financial Aid rejection reply', $$<p>Assalamu alaikum,</p>
<p>Thank you for reaching out to the Muslim Legal Fund of America (MLFA).</p>
<p>We would like to clarify that our organization does not provide direct personal financial assistance. Rather, MLFA supports and funds legal representation in select cases that impact the civil liberties and constitutional rights of Muslims in America. For this reason, we are not able to offer the type of financial assistance you are requesting.</p>
<p>If you have a legal matter that you would like us to consider, you may complete an official inquiry for our attorneys to review: <a href="https://mlfa.org/application-for-legal-assistance/">Application for Legal Assistance - MLFA</a></p>
<p>We sincerely hope that you are able to find the resources and support you need, and we pray for ease and better days ahead.</p>
<p>Sincerely,<br>The Muslim Legal Fund of America</p>$$, true);
