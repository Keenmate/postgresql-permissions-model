# D-13 design: tenant actions and rule mappings replace default groups

Agreed with the user on 2026-11-15. Not implemented yet.

## Why

`unsecure.recalculate_user_groups` runs at every login and on every permission-cache miss. It adds
the user to every `is_default` group in **every** tenant, inactive ones included. A tenant owner can
mark one of their groups as default and pull every user of the system into their tenant, emails
included (reproduced). Default groups also have no rules: "everyone, everywhere" is the only option.

Default groups are removed. Two mechanisms replace them, both using the same rule evaluator:

| | when | effect |
|---|---|---|
| **tenant action** | on registration / on entry / on leave | one-shot steps: join, assign, notify, provision |
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
- **Ops:** `is`, `is_not`, `is_one_of`, `is_not_one_of`, `ends_with`, `regex` (case-insensitive) and
  `includes` (an array contains the value). More ops are added only when a real case needs one.
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

## Tenant actions

```
auth.tenant_action        tenant_id, code, title, is_active, sequence,
                          event_code (on_registration | on_entry | on_leave),
                          rule jsonb, run_once_per_user boolean
auth.tenant_action_step   tenant_action_id, sequence, step_type_code, executor_code,
                          condition_code, is_required, payload_template
auth.tenant_action_run, auth.tenant_action_run_step     the run log, status and results per step
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
