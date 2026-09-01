# What this is, and who it helps

A plain-language overview of the `manager2` trade portal, written for people who
will not read the code: the manager deciding whether to adopt it, and the sales
engineer explaining it.

Two audiences matter throughout, and this document keeps them separate because
they want different things:

- **The client** — the glass manufacturer or fabricator who *operates* the portal.
- **The customer** — the glazier, window installer, joinery or main contractor who
  *buys through* it.

The system only succeeds if it is better for both. A portal that saves the
manufacturer effort by pushing work onto the installer gets abandoned within a
month; installers simply go back to phoning.

---

## 1. The problem it solves

Made-to-measure insulated glass units (IGUs) are sold in a way that has barely
changed in thirty years.

An installer measures an opening on site. He phones or emails a schedule of
sizes — sometimes a photo of a handwritten list. Someone in the office prices it
by hand from a rate card, keys it into a spreadsheet, and emails a quote back.
Two days later the installer accepts, possibly with a change. The order is
retyped into production. A delivery date is agreed verbally. The invoice is
raised separately, from different numbers.

Every step is a place for a transcription error, and in this product a
transcription error is expensive: a unit cut to 1197 mm instead of 1179 mm cannot
be sold to anyone else. It is scrap, plus a remake, plus a delayed site.

**The costs the manufacturer actually carries:**

| Cost | Where it comes from |
|---|---|
| Quoting labour | Hours per day pricing schedules by hand |
| Remakes and scrap | Sizes and specifications transcribed by hand, twice |
| Slow acceptance | Quotes sit in inboxes; the order lands too late for the cutting plan |
| Unplanned production | Orders arrive as a pile, not as a schedule |
| Late invoicing | Invoicing is a separate manual pass, so cash comes in later |
| Unpriced credit risk | Terms are set by relationship and memory, not by payment record |
| Traceability gaps | CE marking obligations met by paper filing (see §5) |

**The costs the installer carries:** waiting for a price when he needs to quote a
homeowner today; no idea what a specification change costs until someone gets
back to him; no visibility of whether his glass arrives Tuesday or Thursday, on a
job where he has booked a fitter and possibly a crane.

---

## 2. What the customer gets

**A price immediately, at their own contract rates.** Enter width, height,
quantity and specification; get the unit price, the line total and the delivery
lead time on screen. No waiting, no phone call, and — this is the part installers
value most — they can price a job *while standing in the customer's house*.

**The cost of a specification change, before committing.** Switch from clear to
solar-control glass, add toughening, move from double to triple: the price, the
U-value and the lead time all update. Today that is three emails and a day's
delay. It also sells better glass, because the installer can see that the upgrade
costs €14/m² rather than guessing it is expensive.

**Their measurements recorded once, by them.** Whoever types the dimensions owns
the error. When the installer enters them directly and confirms them on screen,
the argument about who said 1179 stops happening. Sizes are stored on the order
and reappear on the paperwork and the label.

**Saved delivery sites.** A regular customer delivering to the same three sites
does not re-enter an address, a site contact or "rear loading bay, tail-lift
needed, ring the bell" every time.

**A delivery window they choose, and a firm time when the order is accepted.**
Glass needs someone present, with the right handling equipment. A window that is
selected rather than announced is worth real money to a firm scheduling fitters.

**Repeat and reorder.** Most glazing work is repetitive. Reordering a previous
line — same specification, new sizes — takes seconds.

**One place to ask.** A message thread attached to the order, so "has this
shipped" does not require finding the right person. Support staff can read these,
and the interface says so.

**Their own paperwork, on demand.** Invoices, delivery notes, and the declaration
of performance for the units supplied — without emailing to request a copy.

---

## 3. What the client gets

**Quoting labour largely removed.** Pricing is the rate card, applied
consistently, at three in the morning if that is when the installer is working.

**Orders that arrive as production data.** Dimensions, build-up, coating, tint
and options arrive structured and validated against what the plant can actually
make — maximum pane size, minimum billable area, size increments. An order that
cannot be produced is rejected at entry rather than discovered at the cutting
table.

**A queue instead of a pile.** Orders sort by promised date, customer tier and
payment status. Accept, decline, set a fulfilment date, choose the dispatch
method.

**Invoices raised from the order, correctly, immediately.** Sequential, gapless,
hash-chained, with the customer's verified VAT number and the right tax treatment
— including reverse charge on intra-EU supplies, which is the one that costs money
when it is wrong. Invoicing on the day of dispatch rather than at month-end pulls
cash forward by an average of two to three weeks.

**Credit risk priced on evidence.** Payment behaviour — days late, days
outstanding, overdue balance, failed payments — produces a score and a
recommendation. It is explainable, it can be overridden by a person, and the
reasoning is recorded. It replaces "I think they're usually fine."

**Margin visible per order, not per month.** Cost of goods is captured on every
line at the point of sale, so the manufacturer can see that the smoked units are
carrying the month and the clear double glazing is barely paying for the
production slot.

**Capacity against demand.** Square metres ordered per week against line
capacity: the number that tells the plant manager whether to authorise overtime
on Wednesday or accept a rush order on Thursday.

**Traceability that is already a legal duty, done as a by-product.** See §5.

---

## 4. Why made-to-measure glass fits this especially well

Most B2B ordering portals assume stocked products: a SKU, a quantity, a price.
IGUs break that assumption in ways that make a generic portal useless — and make
a purpose-built one unusually valuable.

**Configured, not picked.** A unit is a build-up (`4-16Ar-4`), a coating, a tint,
a spacer type and two dimensions in millimetres. There is no SKU, and no stock —
only fabrication lead time and capacity.

**Priced by area, with a floor.** Rates are per square metre with a minimum
billable area per unit, so a 300 × 400 mm unit costs the same as a 600 × 900 mm
one. Customers query this constantly. A configurator that shows *billable* area
next to actual area answers it before the phone rings.

**Performance figures are part of the product.** Ug, g-value, light transmittance
and Rw are what the customer is actually buying, and they are what the architect
specified. Showing them change as the specification changes turns the order form
into a specification tool — which is a genuine sales advantage over a competitor
emailing a PDF rate card.

**Bespoke means non-returnable.** A wrongly-sized unit has no resale value. That
raises the stakes on both accurate data capture and payment terms: this is why
deposits on bespoke work and pre-payment for unverified accounts are normal in
the trade, and why the portal enforces an order ceiling until an account is
verified.

**Delivery is a handling problem.** A-frames, stillages, tail-lifts, two-person
handling, glass over a certain area needing equipment. Delivery instructions are
not a nicety here.

**Remakes are a real workflow.** Breakage in transit, a failed unit, a site
measurement error — each needs to be recorded against the original, with fault
attributed, because that determines who pays.

> **Note for the build:** the schema as written assumes stocked SKUs. The
> made-to-measure extension is in `db/schema-glazing.sql` — per-unit dimensions
> and specification on order lines, area-based pricing with a minimum, performance
> values, production capacity, and remake tracking. That file is the adaptation
> layer; the crypto, invoicing, audit and GDPR layers need no changes.

---

## 5. The regulatory argument — and it is a strong one

This section is worth reading properly, because it turns a compliance chore into
the reason to adopt the system.

Insulating glass units are **construction products**. EN 1279-5 is the harmonised
product standard, and CE marking under the EU Construction Products Regulation
applies. That brings three duties:

**A Declaration of Performance for the product** (CPR Art. 4). Required where a
harmonised standard applies. There is a narrow derogation in Art. 5 for
individually-made products, and whether bespoke IGUs fall inside it is a question
for a certifier, not for this document — most series-manufactured made-to-measure
units do not.

**Ten years of records** (CPR Art. 11(2)). The DoP and the supporting technical
documentation must be kept for ten years after the product is placed on the
market.

**Traceability, including who you sold it to** (CPR Arts. 11(4) and 16). Units
must carry type, batch or serial identification. And for ten years, on request,
an economic operator must be able to identify both the suppliers who supplied
them and **the customers to whom they supplied product**.

That last obligation is the point. A manufacturer of CE-marked glass units is
under a **legal duty to know who its customers are, and to be able to prove it a
decade later.** Any ordering system built around anonymous or pseudonymous buyers
is not merely bad practice in this sector — it is unusable, because it cannot
answer the question a market surveillance authority is entitled to ask.

So the portal's identity-first design is not friction added for its own sake. It
produces, as a by-product of taking orders normally:

- a verified legal identity for every trade account, with the VAT number checked
  against VIES and the consultation reference stored as evidence;
- ten years of retained transaction records, already aligned to the ten-year tax
  retention the same business needs anyway;
- the customer-side half of the Art. 16 supply chain record, queryable in seconds
  instead of reconstructed from filing cabinets;
- an audit trail of who accessed what, which is separately useful when a data
  subject asks.

**Two caveats, stated plainly.** First, a revised Construction Products
Regulation (Regulation (EU) 2024/3110) replaces 305/2011 on a phased timetable;
the documentation and traceability duties do not go away, and you should confirm
the transition dates for your product family with your certifier. Second, none of
this makes the software a substitute for AT-certified invoicing in Portugal or for
EN 1279 factory production control — see `docs/SECURITY.md` §4 and
`docs/GDPR.md` §9.

---

## 6. And the privacy side, honestly

The system encrypts the things worth encrypting — site addresses, contact names,
phone numbers, delivery instructions, message bodies — with per-row authenticated
encryption, so a stolen backup or a leaked replica yields nothing readable.

It does **not** encrypt company legal names, VAT numbers or registered addresses,
because those are public registry data and encrypting them would break VIES
checks and invoice rendering while protecting nothing.

It records who decrypted personal data, when, and why — because encryption
without an access record is opacity rather than privacy, including to the people
whose data it is. When a data subject asks, the export tells them which staff
*role* read their details and for what reason.

And it can answer an erasure request correctly, which mostly means knowing what
it may not delete: invoices stay, because tax law requires them and the
customer's identity is mandatory content on the document. The refusal is reasoned
and recorded rather than fudged.

None of this makes an organisation GDPR-compliant on its own — that also needs a
privacy notice, processor agreements, and someone accountable. `docs/GDPR.md` §9
lists what is still outstanding.

---

## 7. What is built, and what is not

**Working and tested** (40 crypto assertions, 81 integration assertions against a
live MariaDB):

- Database schema, including the record of processing activities
- Field-level encryption with key rotation and searchable blind indexes
- Argon2id credentials
- Invitation and business-verification onboarding, with VAT validation
- Payment webhook handling: signature verification, replay protection,
  idempotency, amount reconciliation
- Invoicing: gapless sequential numbering, tamper-evident chain
- Order messaging, encrypted at rest
- Credit scoring with human review
- Access, portability and erasure; retention purge
- Append-only audit trail with tamper detection
- Mobile-first checkout, dark mode, installable PWA

**Not built yet:**

- Login and session controllers (the components exist; the enforcement does not)
- **Tenant scoping** — every customer-facing query must be restricted to the
  signed-in account. This is the most important outstanding item.
- The manager dashboard interface (the data layer and queue ordering exist)
- Catalogue, cart and the made-to-measure configurator as production code
- PDF invoices and delivery notes; DoP generation
- Two-factor enrolment

Realistically this is a solid foundation with the hard and easily-got-wrong parts
done — encryption, payments, invoicing, compliance — and the ordinary web
application work remaining.

---

## 8. Presenting the demo

`demo/index.html` is a self-contained interactive demo. It runs in a browser with
no server and no install, so it works on a laptop in someone's office. It needs no
network to function — offline it simply falls back to system fonts, so if you are
presenting somewhere with no wifi, open it once beforehand to cache the typefaces.
It has an English/Portuguese toggle.

**Suggested five-minute run, in this order:**

1. **Open on the configurator.** Change the height. Let them watch the price,
   the billable area and the cross-section move. Say nothing for a few seconds —
   this is the moment that lands, and it lands better without narration.
2. **Switch the tint to smoked grey.** Point at the g-value dropping and the
   light transmittance dropping with it. This is the upsell conversation their
   sales staff currently have badly over the phone.
3. **Add toughening.** Point at the lead time moving from 5 days to 7. Ask how
   long it currently takes them to tell a customer that.
4. **Go to the order queue.** Note the order flagged as over its credit limit,
   and the unverified account capped at a €250 first order. Ask how that decision
   gets made today.
5. **Accept an order.** Show the invoice number appearing immediately.
6. **Go to the numbers.** Margin per month, and square metres against line
   capacity. Ask when they currently find out they are over capacity.
7. **Close on §5 of this document** — the ten-year duty to identify their
   customers. If they CE-mark, this is already their problem, and the portal
   solves it as a side effect.

**Questions to expect, with honest answers:**

- *"Can it handle our rate card?"* Yes — rates are per square metre by build-up
  and tier, with uplifts per option. The demo's numbers are illustrative; theirs
  go in a table.
- *"Does it integrate with our production software?"* Not yet. The order data is
  structured and exportable; a specific integration is a specific project.
- *"How long to go live?"* Be honest — the foundation is built, the web
  application layer is not. Scope it properly rather than guessing in the room.
- *"Is our data safe?"* Answer with the access log, not the cipher name. Managers
  care that they can see who looked at something.
- *"What about optimisation / cutting plans?"* Out of scope, and say so. Nesting
  and cutting optimisation is a specialist domain and pretending otherwise loses
  credibility with a plant manager immediately.

**Do not claim** the system is GDPR-certified, that the invoicing is
AT-certified, or that CE marking is handled end-to-end. Each is a real limitation
listed above, and a glazing manager will very likely know more about EN 1279 than
you do.
