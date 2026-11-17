# D-13 design: actions, rule mappings and tenant templates replace default groups

Agreed with the user on 2026-11-15/16. Implemented so far: default groups removed (v2.20, `067`); rules, rule mappings and shared rules
(v2.21, `068`); no privilege escalation, D-19 (v2.22, `069`); platform groups (v2.23, `070`); tenant templates (v2.24, `071`); actions (v2.25, `072`).

## Why

`unsecure.recalculate_user_groups` runs at every login and on every permission-cache miss. It adds
the user to every `is_default` group in **every** tenant, inactive ones included. A tenant owner can
mark one of their groups as default and pull every user of the system into their tenant, emails
included (reproduced). Default groups also have no rules: "everyone, everywhere" is the only option.

Default groups are removed. Two mechanisms replace them, both using the same rule evaluator:

| | when | effect |
|---|---|---|
| **action** | on registration / on entry / on leave | one-shot steps: join, assign, notify, provision |
| **rule mapping** on a group | every recalculation | membership follows the rule, both ways |

## Rules

A rule is jsonb in our own format:

```json
{ "mode": "conditional", "combinator": "and", "conditions": [
    { "field": "email_domain",    "op": "is_one_of", "values": ["abc.com", "abc.cz"] },
    { "field": "provider_groups", "op": "includes",  "values": ["FGH Admins"] },
    { "combinator": "or", "conditions": [
        { "field": "provider_code", "op": "is", "values": ["aad"] },
        { "field": "claims.country", "op": "is", "values": ["CZ"] } ] }
] }
```

- **Modes:** `always`, `never`, `conditional`. A rule is mandatory. "Always" has to be written
  explicitly; a missing or empty rule is rejected when saving. A rule nobody wrote never fires.
- **Combinators:** `and`, `or`, with nested groups.
- **Ops:** `is`, `is_not`, `is_one_of`, `is_not_one_of`, `ends_with`, `regex` and `includes`. More ops
  are added only when a real case needs one. As built (v2.21): every field is read as a list (one
  value = a list of one, missing = empty) and compared case-insensitively. `is` / `is_one_of`: any
  element equals a value; `is_not` / `is_not_one_of`: none does; `ends_with` / `regex`: any element;
  `includes`: the list has every value (list fields and claims only).
- **Fields** are read from the user and their **last-used identity**:
  - `email`, `email_domain`, `username`;
  - `provider_code`;
  - `provider_groups`, `provider_roles` (arrays);
  - `claims.<path>`, read from `user_identity.user_data`.
- **Vocabulary:** modes, ops and fields live in `const` tables. An unknown mode, op or field, or an
  invalid regex, is rejected when saving, not at login.
- **No free-text expression language.**
- **One evaluator function** (recursive, set-based), used by both mechanisms.
- **Limit:** provider groups and claims exist only after a login. Pre-provisioned or synced users who
  have never signed in match nothing that depends on them.

## Actions

Named `auth.action` (not `tenant_action`). `tenant_id` is nullable: null = a platform action that
applies in every tenant (kept nullable for now).

```
auth.action               tenant_id (null = platform), code, title, is_active, sequence,
                          event_code (on_registration | on_entry | on_leave),
                          rule jsonb, run_once_per_user boolean
auth.action_step          action_id, sequence, step_type_code, executor_code,
                          condition_code, is_required, payload_template
auth.action_run, auth.action_run_step                   the run log, status and results per step
```

- **The rule is stored on the action.** Each action owns its rule; shared, named rules can come later
  if copies start to hurt.
- **The steps reuse the invitation catalogue and executors:**
  - the database steps run inside the invitation functions;
  - backend and external steps are returned to the app with a filled-in payload, and the app
    reports back when it's done.
- **Steps keep their conditions** (`user_not_in_tenant`, `user_not_in_group`, ...):
  - **the rule** decides whether the action applies to the user;
  - **the condition** decides whether a step still needs doing.
- **Events:**
  - **on_registration:** the user is created in the system. Every tenant's on_registration actions
    are evaluated.
  - **on_entry:** authentication, meaning `ensure_user_from_provider` and the password
    authentication path. Every tenant's on_entry actions are evaluated.
    - `run_once_per_user` off: the action runs at every login.
    - `run_once_per_user` on: it runs only the first time, checked against the run log. This also
      reaches users who registered before the action existed.
  - **on_leave:** the user is explicitly removed from a tenant or from the system. What exactly
    counts is still open, see below.
- **Reverse steps** are needed for on_leave: remove a group member, unassign, revoke resource access.
- **Default groups are gone:**
  - "Everyone joins `basic_users` in tenant 1" becomes an on_registration action with the rule
    `always`.
  - `user_group.is_default` and the default-group branch of `recalculate_user_groups` are removed.
- **As built (v2.25), choices to confirm:**
  - on_entry runs at the end of `ensure_groups_and_permissions` (fresh provider groups and roles),
    not in `ensure_user_from_provider`; on_registration sees only what the registration knows;
  - a platform action runs once per event, not once per tenant, and takes backend and external
    steps only (its database steps would need a tenant);
  - on_leave fires only when a user is deleted, for every tenant they were a member of; leaving one
    tenant waits for the `remove_tenant_user` decision;
  - database steps run on behalf of the author (the last one to save the action);
  - placeholders `{tenant.*}`, `{user.*}`, `{data.*}`; a missing value fails the step, not the event;
  - the reverse steps remove only direct grants (manual memberships, direct assignments);
  - `actions.*` went to `tenant_admin`, `tenant_owner`, `system_admin`, `full_admin` (like `rules.*`),
    `manage_platform_actions` to `full_admin`, `process_action_steps` to `svc_authenticator`;
  - like rule mappings, a tenant action with the rule `always` reaches every user who registers or
    signs in, the exposure default groups had; only `actions.create_action` and D-19 limit it.

## Rule mappings

- **The rule:** `auth.user_group_mapping` gets an optional `rule jsonb`, as an alternative to a
  single `mapped_object_id` / `mapped_role`.
- **Evaluation:** `recalculate_user_groups` evaluates it wherever it handles mappings today, at login
  and on a permission-cache miss.
  - The user matches: they become a member through `mapping_id`.
  - The user no longer matches: the membership is removed.
- **A cache refresh learns nothing new about the user.** The result changes only when the rule or
  mapping was edited (answer **a**: within the cache timeout, like deleting an ordinary mapping today),
  or when the provider or identity is disabled.
- **Example:** an "FGH Admins" group gets the `tenant_admin` perm set and two mappings:
  - an ordinary mapping to Azure FGHAdmins;
  - a rule mapping: `provider_groups includes 'FGH'` **and** `includes 'Finance Leads'`.
- **Synced groups** (`is_synced`) don't take rule mappings. The sync knows members, not claims.

## Event data

Every function that fires an event (`create_tenant`, `delete_tenant`, registration, the leave
functions; `ensure_user_from_provider` already has `_user_data`) accepts `_extra_data jsonb`. It is
stored in the run log and the steps can read it as `{data.*}`, for example the Azure admin group:
`{data.admin_group.id}`, `{data.admin_group.name}`.

## Tenant templates

A **seed**, not a baseline: it runs once, inside `create_tenant`, and the tenant owns everything
afterwards. It creates only the tenant row, groups, perm sets (copied from tenant 1) with their
assignments, and mappings. Anything more is the app's job: `create_tenant` fires a `tenant_created`
pub/sub event when it is done (`pg_notify` from a trigger, the pattern of
`battleplan-notifications.md`; the journal 11001 lets an app catch up on missed events).

```
auth.tenant_template                 template_id, code (null = the default, at most one), title,
                                     description, is_active
auth.tenant_template_group           template_id, code, title, group type, perm_set_codes text[]
auth.tenant_template_group_mapping   template_group_id, provider_code, mapped_object_id /
                                     mapped_object_name / mapped_role (placeholders allowed),
                                     or a reference to a global rule
```

- **Named templates:** e.g. "standard authorization" and "granular authorization".
- **The default template** has no code. It is seeded with today's shape (Tenant Admins with
  `tenant_admin`, Tenant Members with `tenant_member`), can be edited, and cannot be deleted.
  `create_tenant` without `_template_code` uses it.
- **Placeholders:** `{data.*}` (from `_extra_data`) and `{tenant.id}` / `{tenant.code}`. They are
  resolved once, at creation. **A missing value fails `create_tenant`.**
- **Perm sets:** `tenant_owner` is always copied (D-05).
- **As built (v2.24), choices to confirm:** template mappings take a global rule, not an inline
  one; placeholders work in group titles and codes and in mapping values, not inside rules; the
  template permissions (`tenants.manage_tenant_templates` / `read_tenant_templates`) are in
  `system_admin` and `full_admin`; D-19 checks a template's perm sets against the editor in
  tenant 1; using a template needs only `tenants.create_tenant`; `tenant_created` goes out on the
  existing `permission_changes` channel.

## Shared rules

- **Tenant rules** are usable only inside their tenant. Editing one needs `rules.update_rule` there,
  plus D-19: the editor must hold the permissions of everything that references it.
- **Global rules** are owned by tenant 1, usable by every tenant, and editable only with a tenant-1
  permission. That permission is the authority, since D-19 can't be checked across thousands of
  tenants.
- Every edit is journaled with the old and the new rule.
- **Agreed:** the two kinds, tenant and global.
- **Global rules need `rules.manage_global_rules` in tenant 1.** It's a dedicated permission, so it can
  go to a platform team. By default it is in `full_admin` only, not in `system_admin`.
- **Tenant rules:** `rules.create_rule` / `rules.update_rule` / `rules.delete_rule` /
  `rules.read_rules` in the tenant.

## Platform groups (agreed 2026-11-17)

Support staff who oversee tenants. The user's rule: **members of platform groups are never members
of the tenants they support**, at least not visibly. A tenant admin of ABC does **not** see the
members, does **not** see the group, and **cannot** manage it.

```
tenant 1
├─ group "Global Support"  (is_platform)  scope: all tenants
│    mapping → Azure "Support-All"        perm set: platform_admin
├─ group "EU Support"      (is_platform)  scope: ABC, CDE
│    members: Anna, Petr (direct)         perm set: platform_admin
└─ group "FGH Key Account" (is_platform)  scope: FGH
     rule mapping → "in Azure KA-FGH"     perm set: platform_support (narrower)
```

- **The scenarios:**
  - **one support team for every tenant:** one group with scope **all**;
  - **several teams, each with its own tenants:** several groups, each with a list of tenants.
- **Everything lives in tenant 1:** the group, its members, its mappings and rules, and its perm set.
  - The scope is `auth.platform_group_scope (user_group_id, tenant_id)` or a flag for all tenants.
  - **Opting out:** `auth.tenant.allows_platform_access`, set by tenant 1, excludes a tenant even
    from "all".
- **Permission rebuild:** a user in tenant X gets the perm set of every platform group they belong to
  whose scope contains X.
  - The permissions are global and the set is defined once, so nothing is copied into tenants.
  - Platform groups grant nothing in tenant 1 itself unless tenant 1 is in their scope.
- **The tenant contains nothing:**
  - no group, mapping or copy;
  - platform members are not in `auth.tenant_memberships`, so not in user lists, pickers or
    notifications.
- **They see the tenant in their own tenant list.** The available-tenants list adds the tenants in
  their scope, marked as platform access.
- **Permissions, both in tenant 1:**
  - `platform.manage_platform_objects`: groups, members, mappings, scopes;
  - `platform.read_platform_objects`: seeing them.

  Tenant-1 admins without these don't see platform groups either.
- **Journal:** actions in a tenant through platform access are journaled as such.
  - **The tenant sees only "Platform support",** not the person.
  - The name is visible from tenant 1, with `platform.read_platform_objects`.
- **Unchanged from earlier:**
  - the rule is evaluated once per rebuild, to be measured in the perf phase;
  - rule values may carry a label next to the Azure id;
  - the last-used identity rule applies.
- **Replaces** the earlier ideas of a platform-admin rule mapping on every Tenant Admins group, or
  locked platform groups inside each tenant.
- **As built (v2.23), choices to confirm:** "all" skips tenant 1 (list it to cover it); both
  `platform.*` permissions are in `full_admin` only; the opt-out needs
  `platform.manage_platform_objects`; a platform group passes on perm sets and permissions, not
  resource grants; managing a platform group's members needs the platform permission even for its
  group owners.

## Invitations

They stay separate: each one is a one-off with its own scope (a project, a tenant, 10 files). They
share the step catalogue and the executors. Invitation security (D-11) is deferred by the user.

## Open, for later discussion

- **What `remove_tenant_user` removes:**
  - only the Tenant Members group membership; or
  - every direct grant in the tenant: unmapped group memberships, direct assignments, resource access
    and ownership.

  Users who are in through a mapping come back at their next login either way.
- **Whether disable and lock count as on_leave.**
