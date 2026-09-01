# GDPR compliance notes

Encryption is Art. 32 — security of processing. It is good engineering with or
without the regulation, and it is the part everyone builds. This document covers
the rest, which is where compliance actually lives. A system can be encrypted to
the hilt and still be flatly unlawful if it cannot answer *"what do you hold
about me, and will you delete it?"*

---

## 1. Data minimisation, and what it does not mean

Art. 5(1)(c) requires personal data to be *adequate, relevant and limited to what
is necessary in relation to the purposes*. It does not require avoiding identity
where identity is the purpose.

**A trade portal must know its counterparty.** Not for comfort — every downstream
obligation depends on it:

| Requirement | Why identity is unavoidable |
|---|---|
| Valid invoice | Customer legal name and VAT number are mandatory content (VAT Directive Art. 226) |
| Zero-rated intra-EU supply | Requires a verified VAT registration; get it wrong and the **seller** owes the tax |
| Credit terms | Requires someone legally answerable for the debt |
| Contract enforcement | You cannot sue a display handle |
| AML obligations, where they apply | Are literally obligations to identify |

So an account is a legal entity plus at least one named, contactable human.
`users.display_handle` is cosmetic — enough for a UI avatar, so a warehouse
tablet on a shared bench does not show a full name — and never an identity.

**Minimisation here shows up as what is absent.** No date of birth. No ID
document numbers. No home addresses. No personal (as opposed to business)
contact details. No marketing profile absent separate consent. No third-party
enrichment. No behavioural tracking. Per-purpose retention with an automated
purge. Company registry data — legal name, VAT number, registered address — is
**not** encrypted, because it is public information and encrypting it breaks VIES
reconciliation and invoice rendering while protecting nothing.

That is real minimisation. Pseudonymous buyers would not be minimisation; they
would be a portal that cannot invoice.

---

## 2. Record of processing activities (Art. 30)

The ROPA lives in the `processing_purposes` table, not in a spreadsheet that
rots. `RetentionPurger` reads `retention_days` straight off it, so policy and
behaviour cannot drift apart.

| Purpose | Lawful basis | Retention | Notes |
|---|---|---|---|
| `account_admin` | Contract | While live + 24 months | Authentication, user administration |
| `order_fulfilment` | Contract | 3 years after delivery | Delivery address, site contact, access notes |
| `invoicing_tax` | **Legal obligation** | **10 fiscal years** | PT CIVA. Overrides erasure — see §4 |
| `order_support` | Contract | 2 years after thread closes | Order-scoped messages |
| `credit_risk` | Legitimate interest | 5 years | LIA on file. Art. 22 applies — see §5 |
| `security_audit` | Legal obligation | 12 months | Arts. 32, 33 evidence |

Before relying on `credit_risk`, complete a **Legitimate Interests Assessment**:
identify the interest, show the processing is necessary for it, and balance it
against the data subject's rights. Record the outcome and reference it in
`lia_ref`. An untested claim of legitimate interest is the most commonly rejected
basis in enforcement.

**A DPIA (Art. 35) is likely required** for the credit-scoring component, since
it involves systematic evaluation with a significant effect. Do it before go-live,
not after.

---

## 3. Data subject requests (Arts. 15–22)

`src/Gdpr/DsarService.php`

| Right | Article | Implementation |
|---|---|---|
| Access | 15 | `export()` |
| Rectification | 16 | Profile editing + staff correction, audited |
| Erasure | 17 | `erase()` — see §4 |
| Restriction | 18 | `gdpr_requests` workflow |
| Portability | 20 | `export()` returns structured JSON |
| Objection | 21 | `gdpr_requests` workflow |
| Human review of automated decisions | 22(3) | `CreditDecisionService::requestReview()` |

**The clock starts on receipt (Art. 12(3)), not on identity verification.** One
month, extendable by two for genuinely complex requests, with the extension
notified within the first month. A slow verification step does not extend the
deadline. `DsarService::open()` writes `received_at` and `due_at` from a single
timestamp — taking one from PHP's clock and the other from the database's makes
the window compute as 29 days whenever they disagree by a microsecond, and a
deadline quietly a day short is exactly the sort of error that surfaces in
enforcement.

Run `overdueAndDueSoon()` daily and alert on it. A missed deadline is itself an
infringement, and the most common DSAR-related finding.

### The export includes an access log

`_access_log` reports which staff *role* decrypted this person's data, when, and
why. Art. 15(1)(c) requires disclosing recipients, and someone asking "who has
looked at my delivery address" deserves an answer. That is the whole reason
`AuditLog::recordPiiAccess()` exists.

It reports the **role, never the individual employee**. Naming a member of staff
to a third party would be an unlawful disclosure of *their* personal data;
Art. 15(4) makes exactly this reservation.

---

## 4. Erasure: the hard part is what you may not delete

Art. 17(1) grants a right to erasure. Art. 17(3)(b) removes it where processing
is necessary for compliance with a legal obligation.

Invoices are exactly that. Portuguese law requires ten fiscal years of retention,
and the customer's identity is mandatory invoice content. So a valid erasure
request from a customer with invoice history is **partially refused**, and the
refusal must be reasoned, recorded, and communicated together with the right to
complain to the supervisory authority.

**Deleting the invoices instead is not a privacy win. It is tax fraud.**

`erase()` therefore:

**Purges** — name, email, phone, job title, credentials, MFA secret, sessions,
message bodies this person wrote, and (only if they are the last user of the
account) delivery-site contacts and access notes.

**Retains, with the ground recorded** — invoices and their snapshotted billing
identity (17(3)(b)), orders and payments supporting them, and the audit trail
proving the erasure happened (Arts. 5(2), 32).

**Neutralises** — `erased_at` is set, and blind indexes are overwritten with
random bytes rather than nulled, so the account can never be matched or
reactivated while the `UNIQUE` constraint stays meaningful.

One subtlety worth naming: delivery-site contact details are the *employer's*
operational data as much as the individual's. If colleagues still use the site,
erasing them on one person's request would be acting on a request that person
cannot make. `erase()` clears them only when nobody else remains on the account.

---

## 5. Automated decision-making (Art. 22)

`src/Credit/CreditDecisionService.php`

Refusing credit terms materially affects a business, so where the decision is
made without human involvement, Art. 22 applies: the customer must be told, given
meaningful information about the logic, able to express a view, entitled to human
intervention, and able to contest the outcome.

**Implemented as mechanism, not policy:**

- `factors_json` records the actual inputs and their weights, so the explanation
  shown to the customer is *generated from the decision*, not written afterwards
  by someone guessing at it.
- `requestReview()` / `recordHumanReview()` make human intervention a workflow
  with a 14-day SLA and an overdue report, not a mailbox.
- An adverse automated decision raises an ops notification, because a decision
  nobody is told about cannot be contested.
- A decision a human makes or reviews sets `is_automated = 0` — outside Art. 22
  entirely.

**It scores conduct, not people.** Inputs are the account's own record with us:
invoices issued, invoices settled, days late, days outstanding, overdue balance,
failed payments. No credit bureaux. No data about the individual buyer. No
proxies for protected characteristics. No inference from location or sector. The
subject of the decision is the company, and the evidence is its behaviour.

One bug found during testing is worth recording, because it is the failure mode
this kind of code invites: the on-time-payment bonus was gated on *average days
late*, and `AVG` over zero settled invoices is zero — so an account that had
never paid anything scored as a model payer. Absence of evidence read as evidence
of good conduct, in the direction that extends credit. The fix requires settled
invoices to exist before the bonus applies.

**The distinction from a "reliability blacklist" is structural, not cosmetic.**
This is explainable, contestable, human-reviewable, scoped to payment conduct,
retained on a schedule, and disclosed to the customer. A blacklist is none of
those things.

---

## 6. Order messaging: not end-to-end encrypted, and it says so

`messages.body_enc` is encrypted at rest. It is **not** E2EE — staff can read
it, because order support requires reading it.

The UI must say so, and the privacy notice must say so. Claiming end-to-end
encryption where the server holds the keys is a false statement to the customer
and a misrepresentation in the privacy notice. If you genuinely need E2EE, the
keys cannot live in `KeyRing`, and staff cannot answer support queries.

---

## 7. Breach notification (Arts. 33–34)

`breach_register` carries the Art. 33(5) documentation requirement: nature,
categories and approximate number of subjects, likely consequences, measures
taken.

- **72 hours** from becoming *aware* to notify the supervisory authority (CNPD in
  Portugal), unless unlikely to result in risk.
- **Without undue delay** to affected individuals where the risk is high.
- Document even breaches you decide not to notify, with the reasoning. "We
  assessed it as low risk" is defensible; "we did not write it down" is not.

`authority_due_at` should be set to detection + 72h so the deadline is visible
rather than remembered.

Field encryption is directly relevant to Art. 34(3)(a): a breach of properly
encrypted data whose keys were not compromised may not require notifying
individuals. That defence needs evidence — key custody records, and the audit
trail showing what was accessed.

---

## 8. Processors and transfers

`processing_purposes.recipients` and `transfers_outside_eea` are the register.
For each processor you need an Art. 28 data processing agreement, and for any
transfer outside the EEA an Art. 46 safeguard (adequacy decision, or SCCs plus a
transfer impact assessment).

Watch the ones that do not feel like processors:

- **PSP** — receives order references and amounts. Has its own DPA and retention.
- **Carriers** — receive delivery address and site contact. Genuinely necessary.
- **Chat notification endpoint** — this is why `Notification` carries only
  identifiers and refuses anything resembling contact PII at construction. A
  chat message reading *"New order from Ana Ribeiro, deliver to Rua X 12"* copies
  personal data into a third-party service with its own retention, its own
  jurisdiction and its own breach history, outside every control in this codebase
  and outside the ROPA. Making that structurally impossible beats relying on
  discipline at the call site.
- **Email** — the channel of record. Self-hosted or contractually covered.
- **VIES** — an EU Commission service; the VAT number you send is company data,
  not personal data.

---

## 9. What is still missing before go-live

Code cannot supply these.

- [ ] **Privacy notice** (Arts. 13–14) covering identity of the controller, all
      purposes and bases, retention periods, recipients, transfers, rights, and
      the automated decision-making in §5. Version it — `consent_records`
      records which version a user saw.
- [ ] **LIA** for `credit_risk`.
- [ ] **DPIA** (Art. 35) for the credit-scoring component.
- [ ] **Art. 28 DPAs** with every processor in §8.
- [ ] **DPO or a named responsible person.** A DPO is mandatory only in the
      Art. 37 cases, but someone must own this. Set `M2_DPO_EMAIL` and route
      requests to a monitored mailbox.
- [ ] **Staff access policy and training.** The audit log tells you who read what;
      it does not tell you whether they were allowed to.
- [ ] **Incident runbook** wired to `breach_register` with the 72-hour clock.
- [ ] **Retention dry-run signed off.** Run `RetentionPurger::plan()` and have
      someone who understands the commercial consequences approve the numbers
      before `execute()` runs on production data.
- [ ] **Legal review of the Portuguese invoicing route** (see SECURITY.md §4).

---

## 10. A note on the word "GDPR-compliant"

No codebase is GDPR-compliant on its own. Compliance is a property of an
organisation: its documentation, its contracts, its staff behaviour, and its
ability to answer a regulator. This code provides the technical measures Art. 32
requires and the machinery Arts. 15–22 need, which is a genuine and substantial
part of it — and none of the paperwork above.

Be equally careful with "privacy-first" as a phrase. It is a claim about
minimising what you collect, being honest about what you keep and why, and giving
people real control. It is not a synonym for making data hard to attribute. If a
feature's only function is to make it difficult to establish who did what, that
is not privacy engineering — and it tends to be the thing a regulator, an auditor
or a court asks about first.
