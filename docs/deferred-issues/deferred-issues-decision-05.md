# Deferred issues — Decision 5 (repository, licensing, naming)

These issues capture concerns deferred from the initial v1 setup of the
public repository and licensing posture. Filed against the `repo-governance`
epic.

---

## Issue: Trademark registration for "FatFinger6000"

**Labels:** `epic:repo-governance`, `area:legal`, `priority:low`, `type:legal`

**Summary**
Apache 2.0 does not grant trademark rights. If preventing confusingly-named
forks matters, "FatFinger6000" should be registered as a Korlogos / Pitt
Street Labs trademark.

**Acceptance criteria**
- Trademark search confirming the name is available in the relevant classes
  (most likely IC 9 software, IC 42 SaaS / cybersecurity services)
- USPTO trademark application filed if available
- `TRADEMARKS.md` added to the public repo documenting the trademark posture
  and acceptable use guidelines for the name and any associated marks
- README updated with trademark notice

**Triggers**
- First public release with significant external visibility
- First indication of a fork using the name in a commercial context
- Korlogos commercial offering built on the engine

**Estimated effort:** Legal work, ~$300-500 USPTO filing fees plus attorney
time if used. Self-filed is feasible but riskier.

---

## Issue: Contributor License Agreement (CLA) vs. Developer Certificate of Origin (DCO) decision

**Labels:** `epic:repo-governance`, `area:legal`, `priority:medium`, `type:legal`

**Summary**
Apache 2.0 projects typically require either a CLA (signed agreement
transferring or licensing rights to the project) or a DCO (per-commit
sign-off attesting the contributor has the right to submit). Decide which
posture FatFinger6000 takes before accepting external contributions.

**Tradeoffs**
- DCO: lighter weight, well-tolerated by community, sufficient for most OSS
  projects, used by Linux kernel and most CNCF projects
- CLA: heavier weight, can deter casual contributions, but provides stronger
  position for relicensing or commercial flexibility
- Given the engine-public + rulepacks-private split, the engine's licensing
  flexibility is already preserved; CLA may not add enough value to justify
  the friction

**Recommendation**
DCO with `Signed-off-by:` requirement enforced via DCO bot in GitHub Actions.
This is the lighter posture and does not impede the dual-repo strategy.

**Acceptance criteria**
- `CONTRIBUTING.md` with DCO requirement clearly documented
- DCO bot configured on the public repo
- Documentation explaining what DCO sign-off means for new contributors

**Estimated effort:** 1 day

---

## Issue: Security disclosure policy and SECURITY.md

**Labels:** `epic:repo-governance`, `area:security`, `priority:high`, `type:documentation`

**Summary**
Public security tooling needs a clear vulnerability disclosure policy. Where
do researchers report security issues in FatFinger6000 itself? What's the
response SLA? What's the credit policy?

**Acceptance criteria**
- `SECURITY.md` in the public repo describing:
  - Reporting channel (private GitHub Security Advisory, with a backup email)
  - Scope (engine code, build pipeline, official rule pack examples; out of
    scope: third-party rule packs, deployment-specific configurations)
  - Response SLA (first acknowledgment within 72 hours, triage decision
    within 7 days, fix or mitigation timeline based on severity)
  - Coordinated disclosure timeline (90 days standard, with extension
    process)
  - Credit policy (security advisory acknowledgment, optional public credit
    in release notes)
  - Bug bounty posture (none for v1; revisit when project visibility grows)
- GitHub Security Advisory enabled on the repo
- Issue templates configured to redirect security reports to the private
  channel

**Estimated effort:** 1 day

---

## Issue: Public rule pack example library

**Labels:** `epic:repo-governance`, `area:rulepacks`, `priority:medium`, `type:content`

**Summary**
The engine is meaningless without rule packs. The public repo needs a
demonstrable example library so operators can run a meaningful pipeline
without access to private Korlogos content.

**Acceptance criteria**
- `examples/rulepacks/` directory in public repo containing:
  - Generic enterprise attribution rules (rules that apply to any org)
  - Cloud-provider-specific signal rules (AWS, Azure, GCP) — these are
    public knowledge and belong in the public repo
  - Common tech-stack fingerprint signatures (Wappalyzer-equivalent rules)
  - Public CT log seed expansion patterns
- Example seeds (anonymized or public-org-only) demonstrating end-to-end
  pipeline runs
- `examples/rulepacks/README.md` explaining what each example pack covers
  and how to adapt
- CI runs the pipeline against the example pack as an end-to-end test on
  every PR

**Out of scope**
Anything client-specific. Anything that could leak information about
Korlogos engagement work.

**Estimated effort:** 2-3 sprints (substantial content work, can be
incremental)

---

## Issue: Code of Conduct and community moderation policy

**Labels:** `epic:repo-governance`, `area:community`, `priority:low`, `type:documentation`

**Summary**
Public repos accepting external contributions need a Code of Conduct and a
moderation policy. Most projects adopt the Contributor Covenant.

**Acceptance criteria**
- `CODE_OF_CONDUCT.md` in public repo (Contributor Covenant 2.1 recommended)
- Reporting mechanism for code of conduct violations
- Documented enforcement process and consequences
- Link from `README.md` and `CONTRIBUTING.md`

**Estimated effort:** Half a day

**Trigger**
First external contribution or visible community engagement.

---

## Tracking summary

| Issue | Priority | Effort | Trigger |
|---|---|---|---|
| Trademark registration | Low | Legal + filing fees | Significant external visibility |
| CLA vs. DCO decision | Medium | 1 day | Before accepting external contributions |
| SECURITY.md and disclosure policy | High | 1 day | Before any public release |
| Public rule pack example library | Medium | 2-3 sprints | Concurrent with v1 development |
| Code of Conduct | Low | 0.5 day | First external contribution |

Two issues are blocking for "before any public release" — SECURITY.md and the
CLA/DCO decision. Both are cheap. The example rule pack library is bigger work
but can grow incrementally; v1 launch needs at least one minimal example to
demonstrate the engine.
