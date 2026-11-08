# Permission model audit

A domain-by-domain audit of the permission model: find bugs and weak spots, and above all
missing tests. Performance testing comes after this audit and uses the `perf` tags collected here.

## Layout

| Path | What |
|---|---|
| `spec/NN-<domain>.md` | **How it should work.** Invariants per domain. Written by the owner. Agents check the code against these. |
| `decisions.md` | Cross-domain design decisions distilled from the specs' open questions. Answers are applied back to the specs. |
| `findings/NN-<domain>.md` | Findings from the analysis pass, one file per domain. |
| `coverage.py` / `coverage.md` | Which functions are called by any test. Regenerate with `python audit/coverage.py`. |
| `../tests/test_audit_<domain>/` | Tests written in the verify pass. A failing test confirms a finding. |

## Process

1. **Spec**: drafted from code, docs and tests. Every rule taken from the code rather than the
   docs is marked **[confirm]**. The owner reviews each one and either removes the marker or
   rewrites the rule. *A spec rule must never be "whatever the code does now".*
2. **Analyze** (read-only, one agent per domain, using the `audit-domain` skill): check each
   invariant against the code and write findings.
3. **Verify**: write a test for each finding and run it. A failing test means the finding is
   **CONFIRMED**; it stays as a regression test once fixed. If the test passes, the finding is
   **REJECTED** and the test is kept if it adds coverage.
4. **Fix**: in the next `NNN_update_permissions_v2-N.sql` scripts, following CLAUDE.md.

## Domains

| # | Domain | Scope |
|---|---|---|
| 01 | Registration & ensure | `register_user`, `ensure_user_from_provider`, identities, provider user data, invitations, service users |
| 02 | Authentication | login events, tokens, MFA + MFA policy, auto-lockout, blacklist, disabled/locked/deleted users |
| 03 | Group membership | internal / external / hybrid groups, mappings, last-used identity, default groups |
| 04 | Permission calculation | `has_permission(s)`, assignments, perm sets, permission tree, short codes, cache and its invalidation |
| 05 | Tenancy & ownership | tenants, tenant users, `resolve_cross_tenant_access`, owners, soft delete, `*_as_system` helpers |
| 06 | API keys | technical users, key create/rotate/expire/delete, permissions on keys, outbound keys |
| 07 | Resource access | resource access, resource paths, resource roles |
| 08 | Cross-cutting | `security definer` / `search_path`, grants, schema boundaries, the user-1 shortcut, races, null/empty input, audit trail completeness |

## Spec file template

```markdown
# NN - <Domain>

## Scope
Functions, tables and triggers in this domain (with `file:line` from db-objects.md).

## Actors & preconditions
Who calls what (end user, admin in own tenant, admin in tenant 1, system, API key) and what
must already exist.

## Invariants
Numbered, testable rules. One rule per line. Each rule says what must hold, not how it is coded.
- **I-NN-01** <rule>. Source: docs/<file> | code <file:line> **[confirm]** | test <suite>
- ...

## Flows
Step-by-step happy path for each main operation, with the state each step must leave behind
(rows, cache, events, journal).

## Failure behaviour
For each operation: which error code is expected for each bad input or forbidden caller.

## Open questions
Places where docs, code and tests disagree, or where intent is unclear. The owner answers these.

## Known coverage
Existing test suites touching this domain, and invariants with no test.
```

## Finding template

```markdown
### F-NN-001 <one-line title>
- **Severity**: critical | high | medium | low | perf
- **Confidence**: high | medium | low
- **Invariant**: I-NN-xx (or "none - spec gap")
- **Location**: `file.sql:line` (`schema.function`)
- **Scenario**: concrete inputs and state -> what happens -> what should happen
- **Existing tests**: suite/file, or "none"
- **Proposed test**: the steps and the assertion that would fail today
- **Status**: OPEN | CONFIRMED | REJECTED | FIXED (vX.Y)
```

Severity guide: **critical** = cross-tenant data access, privilege escalation, authentication
bypass. **high** = wrong permission result, a disabled/locked user still gets in, a stale cache
grants access. **medium** = missing audit event, wrong error code, data corruption needing manual
repair. **low** = inconsistency, API contract or naming violations. **perf** = a performance
suspect to feed into the performance phase.
