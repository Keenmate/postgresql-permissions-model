# Use cases: a checklist

The ways this model is expected to be deployed. Check every design decision, every fix and
every test plan against this list: does it work in each scenario, and does it break none?

Each scenario lists an example, the features it uses, how a user **gets in** and **leaves** a
tenant, what the model does **today** (v2.26), its **gaps**, and the tests that cover it.
Statements marked **[check]** are not verified against the code yet.

**Leaving is explicit (decided 2026-11-23).** on_leave fires only when something removes the user:
deletion today, later an explicit "remove from tenant" / "leave tenant" call. Where the IdP or a
sync decides (1, 3, 7), there is **no leave event, by design**: detecting it needs a membership
snapshot and periodic full rechecks (tried as v2.27 and reverted: too heavy at 600k users, and
guesswork). Such apps react from their own data (the sync job knows whom it removed; the app can
query `auth.tenant_memberships`).

## At a glance

| # | Scenario | Gets in by | Leaves by | Who decides |
|---|---|---|---|---|
| 1 | Shared IdP pool, members from mappings | provider group mapping at login | dropping out of the provider group | the IdP |
| 2 | Shared IdP pool, members from our groups | admin adds to a group / assigns a perm set | admin removes | a person |
| 3 | Shared IdP pool, rules and actions | a rule matches, an action seeds access | the rule stops matching | the IdP data |
| 4 | Each tenant registers its own users | registration or invitation | admin removes / account deleted | a person |
| 5 | B2B SaaS, one user in many tenants | accepting an invitation | owner removes / user leaves | a person, the user |
| 6 | Self-service onboarding | creating a tenant (becomes owner) | handing over ownership / deleting the tenant | the user |
| 7 | Directory sync driven | pre-provisioning + sync job | the sync job | HR / the directory |
| 8 | Support / operator staff (MSP) | platform group in tenant 1 | removed from the platform group | tenant 1 |
| 9 | Mixed population in one tenant | mapping (employees), invitation (guests) | each by its route | mixed |
| 10 | A separate IdP per tenant | the tenant's own provider | disabled at that provider | the tenant's IdP |
| 11 | Sharing a single resource | a resource grant | the grant is revoked | a person |
| 12 | Integrations and service accounts | an API key | the key is deleted or expires | a person |
| 13 | Single-tenant app | provider role mapping | dropping out of the role | the IdP |

"Who decides" matters for leaving: where **a person** decides, something calls a function and
`on_leave` can run there; where **the IdP or a sync** decides, nobody calls anything and leaving
can only be detected. Scenarios 8, 11 and 12 aren't real membership, so `on_leave` probably
shouldn't apply.

---

## 1. Shared IdP pool, members from mappings to provider groups

**Example:** DHL, one big app, a tenant per department, all users in one Azure AD. Department
membership = an AAD group.

**Uses:** provider with `allows_group_mapping`, group mappings (`create_user_group_mapping`),
tenant templates with `{tenant.code}` / `{data.<path>}` placeholders in the mappings (v2.24).

- **Gets in:** logs in; `ensure_groups_and_permissions` stores the mapped memberships.
- **Leaves:** removed from the AAD group; the mapped membership drops at their next login (or the
  next sync, if the group is synced).
- **Today:** works. No leave event, by design (see the top); on_leave fires only on deletion.
- **Gaps:** someone who never logs in again stays a member until a sync or a login.
- **Tests:** `test_audit_preprovisioning`, `test_audit_tenant_templates`, `test_provider_crud`.

## 2. Shared IdP pool, members from our groups and direct assignments

**Example:** the same AAD, but a tenant admin picks who's in: adds people to the tenant's groups
or assigns perm sets.

**Uses:** internal/hybrid groups, `create_user_group_member`, `assign_permission`, tenant admin
and owner roles (v2.26: only owners hand out `tenant_admin`).

- **Gets in:** an admin adds them (the user may not have logged in yet: pre-provisioning, v2.18).
- **Leaves:** an admin removes each group membership and assignment one by one.
- **Today:** works, but there's no single "remove from tenant"; on_leave fires only on deletion.
  `tenant_admin` has `groups.*` but no `permissions.*`, so admins can't assign perm sets directly
  (D-08 open).
- **Gaps:** an explicit `remove_tenant_user` that removes everything direct and fires on_leave;
  `tenant_admin` contents (D-08).
- **Tests:** `test_audit_admin_hierarchy`, `test_audit_escalation`, `test_audit_tenant_membership`.

## 3. Shared IdP pool, rules and actions

**Example:** "everyone with `@dhl.com` and claim `department = finance` is in Finance; on their
first login add them to Finance Readers and tell the app to create a mailbox".

**Uses:** rules and rule mappings (v2.21), actions on_registration / on_entry (v2.25), backend
steps processed by the app.

- **Gets in:** a rule matches at login or rebuild (member type `rule`); actions seed extra access.
- **Leaves:** the rule stops matching; the rule membership drops at login or rebuild.
- **Today:** works for the rule membership. What actions gave out (direct memberships, perm sets)
  **stays** after the rule stops matching; no leave event (by design).
- **Gaps:** actions are one-way: give lasting access through groups the rule fills, and use
  actions for one-shot effects.
  Defaults to be seen in testing (answers 6-8).
- **Tests:** `test_audit_rules`, `test_audit_actions`.

## 4. Each tenant registers its own users

**Example:** a web app per customer, users sign up with email/password or Google.

**Uses:** `register_user`, `create_user_login_attempt`, `ensure_user_from_provider`, invitations,
on_registration actions.

- **Gets in:** registers, then an invitation or an on_registration action makes them a member.
- **Leaves:** an admin removes them, or the account is deleted (`on_leave` for every tenant).
- **Today:** user accounts are global, not per tenant: the same email is the same user in every
  tenant. on_registration runs the actions of every tenant whose rule matches; nothing tells it
  which tenant's site the user signed up on **[check]** (it could come through `{data.*}`).
- **Gaps:** "signed up on tenant X" context for registration; per-tenant removal (item 1).
- **Tests:** `test_registration_login_events`, `test_audit_registration`, `test_audit_actions`.

## 5. B2B SaaS, one user in many tenants

**Example:** an accountant serving several client companies, each a tenant, invited by email.

**Uses:** invitations (`create_invitation`, `accept_invitation`, invitation actions such as
`add_tenant_user`), tenant switching (`update_user_last_selected_tenant`).

- **Gets in:** accepts an invitation; its actions run.
- **Leaves:** the owner/admin removes them, or **the user leaves on their own**.
- **Today:** invitations work; there's no self-service "leave this tenant".
- **Gaps:** self-leave; invitation security (D-11); per-tenant removal (item 1).
- **Tests:** `test_audit_cross_tenant` (invitation scoping), `test_audit_tenant_membership`.

## 6. Self-service onboarding

**Example:** a user signs up and creates their own company tenant, becoming its owner; the
template gives it the standard groups.

**Uses:** `create_tenant(_tenant_owner_id, _template_code, _extra_data)` (v2.24), owners,
`delete_tenant` (own-tenant soft delete).

- **Gets in:** creates the tenant and becomes its owner.
- **Leaves:** hands ownership to someone else and steps out, or deletes the tenant.
- **Today:** `create_tenant` needs `tenants.create_tenant` **in tenant 1**, so the app has to call
  it as a service user on the user's behalf. Nothing stops the last owner from removing themselves
  **[check]**.
- **Gaps:** a "may create one tenant" permission or a sanctioned service-user flow; last-owner
  protection; ownership hand-over as one step.
- **Tests:** `test_audit_tenancy`, `test_audit_owner`, `test_audit_tenant_templates`.

## 7. Directory sync driven

**Example:** HR feeds the directory; a sync job fills `is_synced` groups before people ever log
in; leavers are removed by the job.

**Uses:** pre-provisioning (`ensure_user_info`, v2.18), group sync (`groups.sync_members` in
tenant 1, v2.19), claiming the account at first login.

- **Gets in:** pre-provisioned and synced in; claims the account at first login.
- **Leaves:** the sync job removes the membership; an HR leaver is disabled or deleted by the app.
- **Today:** works; login leaves synced groups alone. A sync removal is no leave event (by design;
  the sync result lists the removed members). Disable is not leaving.
- **Gaps:** an HR-driven "disable" event, if ever needed.
- **Tests:** `test_audit_group_sync`, `test_audit_preprovisioning`.

## 8. Support / operator staff (MSP)

**Example:** the vendor's support team sees every customer tenant without being members of any.

**Uses:** platform groups (v2.23), scope (all tenants but 1, or a list), tenant opt-out
(`allows_platform_access`), platform actions (backend/external steps only).

- **Gets in:** added to a platform group in tenant 1.
- **Leaves:** removed from it; access disappears at once.
- **Today:** works. The tenant sees no member and no group, and the journal shows "Platform
  support".
- **Gaps:** none known; `on_leave` shouldn't apply (they were never members).
- **Tests:** `test_audit_platform_groups`.

## 9. Mixed population in one tenant

**Example:** employees through Azure AD, outside contractors with email/password, in the same
tenant.

**Uses:** mappings or rules for employees (rules can test `provider_code`), invitations for
guests.

- **Gets in / leaves:** each by its own route (scenario 1 or 3 for employees, 5 for guests).
- **Today:** works. A guest who later gets an AAD account becomes a second user: no linking by
  username (v2.4) unless someone calls `create_user_identity_link`.
- **Gaps:** a documented guest-to-employee path.
- **Tests:** `test_audit_registration`, `test_audit_rules`.

## 10. A separate IdP per tenant

**Example:** every client brings its own Azure tenant or Keycloak realm.

**Uses:** one provider per client; rules or mappings on `provider_code`.

- **Gets in:** logs in through the tenant's provider; a rule on `provider_code` (or a mapping)
  makes them a member.
- **Leaves:** disabled at that provider; their memberships stay until something removes them.
- **Today:** providers are global (managed in tenant 1, v2.15); nothing ties a provider to a
  tenant, so it's emulated with rules.
- **Gaps:** a provider-to-tenant binding (and a tenant admin managing their own provider?).
- **Tests:** `test_provider_crud`, `test_audit_global_ops`.

## 11. Sharing a single resource

**Example:** a document or folder shared with someone outside the tenant.

**Uses:** resource grants and roles (v2.13 / v2.14).

- **Gets in:** a resource grant.
- **Leaves:** the grant is revoked.
- **Today:** a resource grant **makes them a tenant member** (v2.17), so they show up in member
  lists and could fire tenant actions.
- **Gaps:** decide whether a resource grant should count as membership.
- **Tests:** `test_audit_resource_access`, `test_audit_tenant_membership`.

## 12. Integrations and service accounts

**Example:** an ERP integration with an API key in one tenant.

**Uses:** API keys and their technical users, permissions on keys.

- **Gets in:** an API key is created (a technical user with direct assignments).
- **Leaves:** the key is deleted or expires.
- **Today:** the technical user counts as a tenant member through its assignments **[check]**.
  Whether actions run for technical users **[check]**.
- **Gaps:** technical users should probably be skipped by actions and hidden from member lists.
- **Tests:** `test_tenant_scoping_security`, `test_audit_cross_tenant`.

## 13. Single-tenant app

**Example:** an internal tool, tenant 1 only, permissions from AAD roles.

**Uses:** role mappings, tenant 1.

- **Gets in / leaves:** by AAD role, at login.
- **Today:** works; tenancy is invisible.
- **Gaps:** make sure nothing multi-tenant gets in the way (tenant 1 exceptions such as templates,
  platform groups, owner-only sets).

---

## Checklist for every decision or change

1. In which scenarios does it come up? Walk each one.
2. How does a user get in and leave there, and does the change keep both working?
3. Who does it: the user, a tenant admin, a tenant owner, tenant 1, a service user, the IdP?
   Do D-19 and owners-above-admins (v2.26) still allow the legitimate path?
4. What does the tenant see (members, groups, journal) and what must it not see (platform staff,
   other tenants)?
5. Disabled, locked or deleted users, soft-deleted tenants, inactive providers: still nothing
   granted?
6. Cache: does the change reach `user_permission_cache` at once?
7. Audit trail: journal and user events written?
8. Is it covered by a test, and in which suite?

## Open questions collected from the scenarios

| Question | Scenarios | Tracked as |
|---|---|---|
| ~~What "leaving a tenant" means~~ (explicit removal only; none for IdP/sync) | 1, 2, 3, 5, 7 | item 1 |
| ~~Do disable / lock count as leaving~~ (no) | 7 | item 1b |
| Explicit `remove_tenant_user` / self-service `leave_tenant` firing on_leave | 2, 4, 5 | item 1 |
| Tenant context for registration | 4 | - |
| `tenant_admin` contents (`permissions.*`?) | 2 | D-08 |
| Invitation security | 5, 9 | D-11 |
| Self-service tenant creation, last-owner protection | 6 | - |
| Provider bound to a tenant | 10 | - |
| Does a resource grant make a member | 11 | - |
| Technical users and actions / member lists | 12 | - |
