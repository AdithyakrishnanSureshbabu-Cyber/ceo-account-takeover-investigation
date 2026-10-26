# Executive Account Takeover Investigation

**SOC Analysis | KQL | Azure Data Explorer | Identity Security**

Investigated a simulated CEO account takeover, identified a second compromised user, uncovered unauthorised MFA registration and finance-mail concealment, and documented response recommendations addressing potential payment fraud and business disruption.

**26 accounts targeted · 2 accounts compromised · 3 attack-source IPs**

[Read the incident report](Cloudora_CEO_Account_Takeover_Incident_Report.pdf) · [View investigation evidence](#investigation-and-evidence) · [Skills demonstrated](#skills-demonstrated)

> **Simulated investigation:** Cloudora is fictional and all supplied incident data is synthetic. This project demonstrates investigation and response planning. Live containment and recovery were not performed or verified.

## Project overview

| Area | Details |
|---|---|
| Analyst | Adithyakrishnan Sureshbabu |
| Scenario | CEO account takeover — Cloudora |
| Incident reference | CLD-0001 / CLD-IR-0001 |
| Scenario priority | P1 — executive account compromise |
| Incident period | 8–10 August 2026 |
| Investigation platform | Azure Data Explorer |
| Query language | Kusto Query Language — KQL |
| Evidence | Synthetic Entra ID sign-in and audit logs |
| Deliverables | Incident report, investigation screenshots, and response recommendations |

## Executive summary

Cloudora was approaching an important enterprise deal when its IT administrator reported suspicious early-morning access to the CEO’s account. The investigation needed to establish whether the account was compromised, identify other affected users, and assess the potential consequences for payments, confidential correspondence, and customer trust.

Using KQL, I reconstructed the sign-in sequence, compared account histories, examined audit changes, and expanded the investigation across the identified infrastructure. The evidence supported compromise of **Daniel Reeve’s and Priya Nair’s accounts**, within a campaign targeting **26 distinct users**.

On the CEO’s account, attacker-associated activity registered an authenticator method named **Pixel 6** and created **RSS Subscriptions**, an inbox rule that concealed finance and invoice-related messages. These findings made identity remediation and independent payment verification immediate response priorities.

The supplied evidence establishes compromise and a credible fraud risk. It does not establish actual financial loss, fraudulent outbound messages, or data exfiltration.

## Key findings

| Finding | Evidence | Why it matters |
|---|---|---|
| CEO account compromised | Failed attempts followed by successful access and unauthorised account changes | Executive identity and mailbox require immediate response |
| Wider credential attack | Failures against 26 accounts from three IPs over three nights | Scope extends beyond the original alert |
| Unauthorised MFA method | Pixel 6 authenticator registered after successful access | Password reset alone leaves an unauthorised method configured |
| Finance-mail concealment | Rule moves finance/invoice messages out of the inbox and marks them read | Could conceal payment discussions or warnings |
| Second compromised account | Priya’s successful sign-ins from campaign infrastructure | Response must include another identity and potential SharePoint exposure |
| Likely legitimate travel | Omar’s Dubai activity is consistent with his successful-use history | Context helps avoid unnecessary disruption |

## Skills demonstrated

- **Azure Data Explorer:** Queried imported sign-in and audit records to investigate suspicious activity.
- **KQL:** Used filtering, projection, aggregation, distinct-account counts, time bucketing, and chronological analysis.
- **Microsoft Sentinel investigation concepts:** Practised KQL-based alert triage, baseline comparison, and incident scoping relevant to Sentinel. This investigation ran in Azure Data Explorer, not a live Sentinel workspace.
- **Identity investigation:** Correlated authentication activity with unauthorised MFA and mailbox-rule changes.
- **Incident scoping:** Distinguished compromised accounts from the wider target population.
- **Evidence validation:** Recognised apparent duplicates and separated row counts from distinct accounts and event combinations.
- **Incident reporting:** Connected technical findings to business risks, response priorities, and evidence limitations.
- **MITRE ATT&CK mapping:** Mapped observed behaviour to relevant techniques.

## Investigation and evidence

**All incident timestamps below are UTC, August 2026.**

Counts reflect my query results. Apparent duplicate records are explained in the [Data quality](#data-quality) section.

### 1. Reconstruct the CEO’s suspicious access

Daniel’s account recorded failed attempts from `102.89.44.17` at **03:09:12** and **03:10:41**, followed by:

| Time, UTC | Successful sign-in |
|---|---|
| 03:12:05 | Microsoft 365 |
| 03:14:30 | Outlook Web |
| 03:26:02 | Azure Portal |

I examined the sequence rather than treating unfamiliar geography as proof of compromise. The subsequent unauthorised account changes strengthened the assessment.

![CEO sign-in timeline showing failures followed by successful access](screenshots/01-triage-ceo-signins.png)

### 2. Compare activity with Daniel’s baseline

The baseline query returned **78 London sign-in rows**:

- **76 rows** from `203.0.113.13`.
- **2 rows** from `203.0.113.11`.

A London sign-in also occurred at **08:41:00** on the incident day.

I assessed the location history alongside the failure sequence, device/browser context, and account changes. The later London sign-in alone does not conclusively exclude VPN use.

![Daniel Reeve location baseline](screenshots/02-daniel-baseline.png)

### 3. Identify the wider password-spraying pattern

Grouping failed sign-ins by source IP and distinct account revealed three sources targeting overlapping user populations.

| Source IP | Failure rows | Distinct targeted accounts |
|---|---:|---:|
| `102.89.44.17` | 96 | 23 |
| `102.89.45.101` | 76 | 20 |
| `102.89.44.23` | 56 | 18 |
| **Combined** | **228** | **26 unique accounts** |

The account populations overlap across IP addresses, so their distinct counts cannot be added together.

The many-account failure pattern is consistent with password spraying. Attempted password values are unavailable, so the exact credential-guessing method cannot be directly confirmed.

![Failed sign-ins grouped by source IP and distinct accounts](screenshots/04-spray-failures-by-ip.png)

### 4. Establish the campaign window

Daily aggregation showed failures across three consecutive nights:

| Date, UTC | Failure rows |
|---|---:|
| 8 August | 88 |
| 9 August | 72 |
| 10 August | 68 |
| **Total** | **228** |

The query also returned **10 successful rows on 10 August**. The separate scope query grouped successful results into five distinct account/IP/timestamp combinations.

This showed why the investigation needed to extend beyond the day of the reported compromise.

![Campaign activity grouped by UTC day](screenshots/05-spray-window-by-day.png)

### 5. Examine authentication and mailbox changes

The audit query revealed two changes on Daniel’s account:

| Time, UTC | Change | Response implication |
|---|---|---|
| 03:18:44 | Authenticator app added with device name `Pixel 6` | Remove the unauthorised method and verify legitimate methods |
| 03:31:09 | Inbox rule `RSS Subscriptions` created | Preserve and remove the rule; review affected finance correspondence |

The rule matches messages from `finance@cloudora.io` or containing `invoice`, moves them to **RSS Feeds**, and marks them read.

Each event appears twice in the screenshot. This does not establish two separate registrations or rules.

**Business implication:** Financial conversations or warnings could be hidden from the CEO, creating an opportunity for invoice fraud. The rule’s creation does not establish that fraudulent messages or payments occurred.

![Audit records showing authenticator registration and inbox-rule creation](screenshots/06-audit-persistence.png)

### 6. Scope successful access beyond the CEO

Searching identified infrastructure for successful sign-ins returned:

| Account | Distinct successful sign-in times, UTC | Source IP |
|---|---|---|
| Daniel Reeve | 03:12:05, 03:14:30, 03:26:02 | `102.89.44.17` |
| Priya Nair | 03:47:18, 03:52:40 | `102.89.45.101` |

This identified **Priya as a second compromised user** and expanded the response scope.

![Successful sign-ins showing both affected accounts](screenshots/07-scope-successful-signins.png)

Priya’s baseline returned **66 London rows** from `203.0.113.10`. Her successful SharePoint Online sign-in creates a potential document-exposure concern; file-operation records are needed to establish which documents were accessed or downloaded.

No audit events target Priya in the supplied audit file. That limited absence does not prove her account had no unauthorised changes.

![Priya Nair location baseline](screenshots/09-priya-baseline.png)

### 7. Inventory the complete target population

The campaign targeted **26 distinct accounts**. Excluding Daniel and Priya leaves **24 accounts with failures only from the identified infrastructure**.

These accounts remain a review population. Failed attempts alone do not establish compromise, and the available evidence does not guarantee that they were unaffected elsewhere.

![Accounts targeted by the campaign](screenshots/08-spray-targeted-accounts.png)

### 8. Assess a likely legitimate travel anomaly

Omar Farah’s baseline returned:

| Location | Sign-in rows |
|---|---:|
| London | 76 |
| Dubai | 24 |
| Lagos, across the three campaign IPs | 12 |

Dubai activity came from `185.93.245.66` across 8–10 August. Supporting log records show successful activity using iOS 17 / Mobile Safari, also present in his London history.

I assessed this as **likely legitimate travel**, with user confirmation appropriate in a live investigation. Omar remained in the campaign review because the identified infrastructure separately targeted his account.

![Omar Farah baseline showing Dubai activity](screenshots/03-omar-baseline-travel.png)

## Business impact assessment

| Concern | Supporting evidence | Recommended follow-up |
|---|---|---|
| Payment diversion | Finance/invoice messages configured to be concealed | Independently verify suspicious payment requests and banking-detail changes |
| Executive impersonation | Successful CEO identity and Outlook Web access | Review message trace and relevant mailbox activity |
| Sensitive information exposure | CEO mailbox and Priya’s SharePoint application access | Review message/file operations and permissions |
| Customer confidence | Opportunity to misuse an executive identity during an important deal | Establish actual exposure before deciding customer communication |
| Operational disruption | Two identities require secure remediation | Arrange approved alternative communication during access restrictions |

**No financial loss, lost deal, or confirmed reputational damage is claimed.**

## Recommended response

These are proposed actions, not verified tenant changes.

| Priority | Action | Purpose |
|---|---|---|
| Immediate | Preserve evidence while promptly restricting sign-in and revoking sessions for both affected accounts | Interrupt attacker access |
| Immediate | Reset credentials and review authentication and recovery settings | Secure both identities |
| Immediate | Remove the unauthorised authenticator method | Resolve the authentication change |
| Immediate | Preserve and remove the inbox rule; inspect forwarding, delegates, and other rules | Restore mailbox integrity |
| Immediate | Independently verify suspicious payment instructions | Reduce potential financial loss |
| Follow-up | Review all targeted accounts and obtain mailbox and SharePoint activity records | Establish wider exposure |
| Before closure | Verify live configuration and fresh telemetry | Demonstrate recovery and document residual risk |

Known-IP restrictions are an additional measure because an attacker can change infrastructure. Previously hidden messages also require review; deleting the rule does not automatically restore them to the inbox.

## MITRE ATT&CK mapping

| Tactic | Technique | Supporting behaviour |
|---|---|---|
| Credential Access | T1110.003 — Password Spraying | Failures distributed across many accounts over three nights |
| Initial Access | T1078 — Valid Accounts | Successful attacker-associated access to Daniel and Priya |
| Persistence | T1098.005 — Device Registration | Unauthorised Pixel 6 authenticator registration |
| Defense Evasion | T1564.008 — Email Hiding Rules | Finance/invoice messages moved out of the inbox and marked read |

## Data quality

Repeated records are visible in the imported sign-in and audit results. The figures below describe rows returned by my queries.

| Measure | Query result |
|---|---:|
| Campaign failure rows | 228 |
| Successful campaign-associated rows | 10 |
| Daniel’s London baseline rows | 78 |
| Priya’s London baseline rows | 66 |
| Omar’s Dubai activity rows | 24 |
| Distinct targeted accounts | 26 |

Apparent duplicates mean row counts should not be interpreted as unique authentication attempts.

The successful-access scope query groups by account, IP address, and timestamp, returning **five distinct combinations across two compromised accounts**.

## Detection improvements

The findings support:

- Password-spray monitoring across distinct users and multiple source IPs.
- Correlation of authentication-method additions with suspicious recent access.
- Monitoring of inbox rules that conceal finance, invoice, or security correspondence.
- Investigation workflows connecting identity activity with mailbox and file operations.
- Ingestion-quality checks before using counts for alert thresholds or incident metrics.

These are proposed improvements. A deployed or production-validated detection rule is not claimed.

## Evidence limitations

The supplied historical logs do not establish specific messages read, documents downloaded, fraudulent payments, customer impact, or successful recovery.

Further evidence requests would include mailbox access records, message trace, SharePoint file operations, payment records, and post-remediation telemetry.

## Lessons learned

- **Scope beyond the initial alert.** Infrastructure-based analysis identified another compromised identity.
- **Account changes determine remediation.** The authenticator registration and mail rule showed why password reset alone was insufficient.
- **Context improves judgement.** Baseline comparison supported different assessments for Daniel’s and Omar’s unfamiliar-location activity.
- **Validate counts before reporting scale.** Repeated records affected event totals without increasing distinct users.
- **Business harm and recovery need evidence.** Potential impact and recommended actions must remain separate from verified outcomes.

## Attribution

The fictional scenario, synthetic datasets, report template, and query guidance were provided by the **MyFirstHack / myfirstcyberjob community**.

The screenshots document my investigation run in Azure Data Explorer. This repository presents my analysis and reporting for learning and portfolio purposes, with queries developed or adapted using the supplied guidance.

This project is not employment or a live client engagement. Original answer keys and another participant’s assessment are not included.
