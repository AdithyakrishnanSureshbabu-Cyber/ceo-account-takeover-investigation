# Executive Account Takeover Investigation

**SOC investigation | Identity compromise | Password spraying | Business email compromise risk**

Investigated a simulated executive account takeover using KQL to reconstruct suspicious access, identify a second compromised user, uncover unauthorised authentication and mailbox changes, and recommend a response focused on financial exposure and customer trust.

**26 distinct accounts targeted · 2 accounts compromised · 3 attack-source IPs**

[Read the incident report](Cloudora_CEO_Account_Takeover_Incident_Report.pdf) · [Review the evidence](#investigation-findings-and-evidence) · [Response recommendations](#recommended-response)

> **Simulation:** Cloudora is fictional and the supplied logs are synthetic. This project demonstrates investigation, analysis, and response planning. Live containment and recovery were not performed or verified.

## Executive summary

A suspicious early-morning sign-in against Cloudora’s CEO raised concerns shortly before an important enterprise deal. The investigation needed to answer both a technical and a business question: **was the executive identity compromised, and could that access expose the company to financial fraud or damage customer confidence?**

I analysed sign-in and audit records in Azure Data Explorer, compared account baselines, traced a wider password-spraying pattern, and scoped successful access across the identified infrastructure.

The investigation identified two compromised accounts. On the CEO’s account, an unauthorised authenticator registration was followed by an inbox rule that concealed finance and invoice-related messages. These changes created a credible opportunity for executive impersonation and payment diversion.

The supplied evidence does not establish actual financial loss, fraudulent outbound messages, or data exfiltration. The response recommendations therefore address immediate access risk while identifying the additional evidence needed to assess business impact.

## Project overview

| Area | Details |
|---|---|
| Analyst | Adithyakrishnan Sureshbabu |
| Scenario | Cloudora CEO account takeover — CLD-0001 |
| Priority | P1, assigned by the training scenario |
| Incident period | 8–10 August 2026 |
| Investigation platform | Azure Data Explorer |
| Query language | Kusto Query Language — KQL |
| Log sources | Synthetic Entra ID sign-in and audit records |
| Deliverables | Incident report, investigation screenshots, and response recommendations |

The investigation used `CloudoraSignIn_CL` and `CloudoraAudit_CL`. The KQL analysis skills are relevant to Microsoft Sentinel investigations; production schemas and detection configuration require adaptation.

## Results at a glance

| Investigation question | Result |
|---|---|
| Was the CEO’s account compromised? | Correlated sign-in and audit evidence supports compromise |
| Was the activity isolated? | No — 26 distinct accounts were targeted across three nights |
| Was another account accessed? | Yes — Priya Nair’s account |
| What changed after CEO access? | Pixel 6 authenticator registration and RSS Subscriptions inbox rule |
| Was every unfamiliar location malicious? | No — Omar Farah’s Dubai activity was assessed as likely legitimate travel |
| Was business harm confirmed? | Fraud and disclosure remain potential consequences requiring further evidence |
| Was recovery verified? | No — response actions were documented as recommendations |

## Investigation findings and evidence

All incident timestamps below are **UTC, August 2026**. Counts describe the query results shown in my screenshots.

### 1. Reconstructing the CEO’s suspicious access

Daniel Reeve’s account recorded failed attempts from `102.89.44.17` at **03:09:12** and **03:10:41**, followed by:

| Time, UTC | Successful sign-in |
|---|---|
| 03:12:05 | Microsoft 365 |
| 03:14:30 | Outlook Web |
| 03:26:02 | Azure Portal |

This sequence established the activity requiring investigation. The subsequent authentication-method and inbox-rule changes strengthened the compromise assessment.

**Analyst decision:** Treat the sign-in as part of a correlated sequence rather than concluding compromise from geography alone.

![CEO sign-in triage showing failures followed by successful access](screenshots/01-triage-ceo-signins.png)

### 2. Establishing Daniel’s location baseline

The baseline query returned **78 London sign-in rows**:

- **76 rows** from `203.0.113.13`.
- **2 rows** from `203.0.113.11`.

The account also recorded a London sign-in at **08:41:00** on 10 August.

I assessed this history alongside the authentication sequence and unauthorised account changes. A later London sign-in alone does not conclusively exclude travel or VPN use.

**Analyst decision:** Use the baseline to support judgement, with the audit changes providing stronger evidence of misuse.

![Daniel Reeve location baseline](screenshots/02-daniel-baseline.png)

### 3. Identifying the wider credential attack

Grouping failed sign-ins by source IP and distinct account revealed three sources targeting overlapping user populations.

| Source IP | Failed-sign-in rows | Distinct targeted accounts |
|---|---:|---:|
| `102.89.44.17` | 96 | 23 |
| `102.89.45.101` | 76 | 20 |
| `102.89.44.23` | 56 | 18 |
| **Combined** | **228** | **26 unique accounts** |

The distinct-account counts overlap across IPs and cannot be added together.

The many-account failure pattern is consistent with password spraying. The logs do not reveal attempted password values or conclusively establish how the successfully used credentials were obtained.

**Analyst decision:** Expand the investigation from one executive account to the complete campaign target population.

![Failed sign-ins grouped by source IP and distinct accounts](screenshots/04-spray-failures-by-ip.png)

### 4. Establishing the campaign window

Daily aggregation returned failures across three consecutive nights:

| Date, UTC | Failed-sign-in rows |
|---|---:|
| 8 August | 88 |
| 9 August | 72 |
| 10 August | 68 |
| **Total** | **228** |

The query also returned **10 successful rows on 10 August**. The separate scope query grouped these into five distinct account/IP/timestamp combinations.

**Analyst decision:** Assess the activity as a multi-day campaign rather than focusing only on the morning of the CEO alert.

![Campaign activity grouped by UTC day](screenshots/05-spray-window-by-day.png)

### 5. Identifying authentication persistence and finance-mail concealment

The audit query revealed two significant changes on Daniel’s account:

| Time, UTC | Audit activity | Security and business significance |
|---|---|---|
| 03:18:44 | Authenticator app added, device name `Pixel 6` | Unauthorised authentication configuration requires removal and verification |
| 03:31:09 | Inbox rule `RSS Subscriptions` created | Finance/invoice correspondence could be hidden from the CEO |

The inbox rule matches messages from `finance@cloudora.io` or containing `invoice`, moves them to **RSS Feeds**, and marks them read.

Each audit event appears twice in the screenshot. This does not establish two authenticator registrations or two separate rules.

**Analyst decision:** Recommend remediation beyond a password reset and involve finance in reviewing potentially concealed correspondence.

**Business implication:** The rule could hide payment discussions or warnings, supporting a potential route to invoice fraud. Its creation does not prove that fraudulent messages or payments occurred.

![Audit records showing authenticator registration and inbox-rule creation](screenshots/06-audit-persistence.png)

### 6. Finding the second compromised account

Searching successful access from the identified infrastructure produced five distinct combinations:

| Account | Successful sign-in times, UTC |
|---|---|
| Daniel Reeve | 03:12:05, 03:14:30, 03:26:02 |
| Priya Nair | 03:47:18, 03:52:40 |

Priya’s successful access came from `102.89.45.101`, one of the campaign sources.

**Analyst decision:** Extend the affected-account scope and proposed response to Priya, rather than closing the investigation around the original CEO alert.

![Successful sign-ins identifying both affected accounts](screenshots/07-scope-successful-signins.png)

Priya’s baseline returned **66 London sign-in rows** from `203.0.113.10`. Her subsequent SharePoint Online sign-in creates a potential document-exposure concern, but file-operation evidence is needed to establish which documents were accessed or downloaded.

![Priya Nair location baseline](screenshots/09-priya-baseline.png)

### 7. Defining the wider account-review population

The target inventory returned **26 distinct accounts**. Excluding the two compromised identities leaves **24 accounts with failures only from the identified infrastructure**.

**Analyst decision:** Include those 24 accounts in further review and consider precautionary credential actions under the response policy.

“No successful access observed” is limited to the supplied evidence. It does not prove that an account was never compromised through other infrastructure or outside the recorded period.

![Accounts targeted by the password-spraying campaign](screenshots/08-spray-targeted-accounts.png)

### 8. Assessing a likely legitimate travel anomaly

Omar Farah’s baseline returned:

| Location | Sign-in rows |
|---|---:|
| London | 76 |
| Dubai | 24 |
| Lagos, across three campaign IPs | 12 |

Dubai activity came from `185.93.245.66` across 8–10 August. Supporting source records show successful activity using iOS 17 / Mobile Safari, a combination also present in his London history.

**Analyst decision:** Assess Dubai activity as likely legitimate travel, with user confirmation appropriate in a live investigation. Retain Omar in the campaign review because he was separately targeted by the identified infrastructure.

![Omar Farah location baseline showing Dubai activity](screenshots/03-omar-baseline-travel.png)

## Business impact assessment

| Business concern | Supporting evidence | Required follow-up |
|---|---|---|
| Payment diversion | Finance/invoice messages configured to be concealed | Independently verify suspicious payment requests and banking-detail changes |
| Executive impersonation | Successful CEO identity and Outlook Web access | Review message trace and relevant mailbox audit evidence |
| Sensitive information exposure | CEO mailbox and Priya’s SharePoint application access | Review message/file operations and permissions |
| Customer confidence | Opportunity to misuse a trusted executive identity during a significant deal | Establish actual exposure before deciding external communications |
| Operational disruption | Two identities require secure remediation | Arrange approved alternative communication while access is restricted |

No monetary loss, lost deal, or confirmed reputational damage is claimed.

## Recommended response

These are proposed actions, not verified tenant changes.

1. **Interrupt access.** Preserve relevant evidence while promptly restricting sign-in and revoking sessions for both affected accounts.
2. **Secure authentication.** Reset credentials, remove unauthorised methods, and verify legitimate authentication and recovery settings.
3. **Restore mailbox integrity.** Preserve and remove the malicious rule; inspect forwarding, delegates, and other rules; review previously hidden messages.
4. **Protect transactions.** Confirm suspicious payment instructions and banking-detail changes through known contact channels.
5. **Investigate wider exposure.** Review targeted accounts and obtain mailbox and SharePoint activity evidence.
6. **Verify recovery.** Check live configuration and fresh telemetry before restoring normal access and closing the incident.

Restrictions on known IPs are an additional control because the attacker may change infrastructure.

## MITRE ATT&CK mapping

| Tactic | Technique | Supporting behaviour |
|---|---|---|
| Credential Access | T1110.003 — Password Spraying | Failures distributed across many accounts over three nights |
| Initial Access | T1078 — Valid Accounts | Successful attacker-associated access to Daniel and Priya |
| Persistence | T1098.005 — Device Registration | Unauthorised Pixel 6 authenticator registration |
| Defense Evasion | T1564.008 — Email Hiding Rules | Finance/invoice messages moved out of the inbox and marked read |

## Detection and monitoring opportunities

The findings support the following improvements:

- Detect failed authentication across multiple distinct accounts, including campaigns distributed across IPs.
- Correlate new authentication-method registration with suspicious recent access.
- Monitor inbox rules that hide finance, invoice, or security messages.
- Connect identity evidence with mailbox and SharePoint activity.
- Validate ingestion quality before using event counts for alert thresholds or incident metrics.

These are proposed improvements. A deployed or production-validated detection rule is not claimed.

## Skills demonstrated

- **Azure Data Explorer:** Queried imported sign-in and audit logs to investigate suspicious account activity.
- **Kusto Query Language (KQL):** Filtered events, grouped failures by source IP, counted distinct targeted accounts, and reconstructed timelines.
- **Microsoft Sentinel investigation concepts:** Practised KQL-based analysis relevant to Sentinel, including alert triage, baseline comparison, and incident scoping. This project was performed in Azure Data Explorer, not a live Sentinel workspace.
- **Identity investigation:** Correlated failed and successful sign-ins with authentication-method and mailbox-rule changes.
- **Incident scoping:** Identified two compromised accounts and distinguished them from the wider targeted population.
- **Evidence validation:** Recognised apparent duplicate records and separated row counts from distinct accounts and events.
- **Incident reporting:** Documented findings, business risks, evidence limitations, and recommended containment actions.
- **MITRE ATT&CK mapping:** Mapped observed behaviour to password spraying, valid accounts, device registration, and email hiding rules.

## Evidence limitations

Historical sign-in and audit logs establish account activity and recorded configuration changes. They do not establish specific messages read, documents downloaded, fraudulent payments, customer impact, or successful recovery.

Further evidence requests would include mailbox access records, message trace, SharePoint file operations, payment records, and post-remediation telemetry.
