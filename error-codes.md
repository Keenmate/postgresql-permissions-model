# Error Codes

Quick reference for all error codes raised by the PostgreSQL Permissions Model. Codes are PostgreSQL `SQLSTATE` values and can be caught with `EXCEPTION WHEN SQLSTATE 'XXXXX'`.

For the full reference (event codes + error codes + legacy mapping + examples), see `../postgresql-permissions-model-docs/docs/codes.md`.

**Code ranges:**

| Range | Type | Description |
|-------|------|-------------|
| 10000 — 29999 | Informational events | Logged to `public.journal` and `auth.user_event` |
| 30000 — 39999 | Errors | Raised as PostgreSQL exceptions |
| 50000+ | Reserved | Application-specific codes |

All errors are seeded in `const.event_code` with matching templates in `const.event_message`. Most are raised via dedicated `error.raise_XXXXX` functions in `016_functions_error.sql`; a few are raised inline at the call site.

---

## Security / Auth (30001 — 30999)

| Code | Name | Raised by | Meaning |
|---|---|---|---|
| 30001 | `err_api_key_invalid` | `error.raise_30001` | API key/secret combination invalid or API user not found |
| 30002 | `err_token_invalid` | `error.raise_30002` | Token invalid or expired |
| 30003 | `err_token_wrong_user` | `error.raise_30003` | Token belongs to a different user |
| 30004 | `err_token_already_used` | `error.raise_30004` | Token already consumed |
| 30005 | `err_token_not_found` | `error.raise_30005` | Token does not exist |

## Validation (31001 — 31999)

| Code | Name | Raised by | Meaning |
|---|---|---|---|
| 31001 | `err_either_group_or_user` | `error.raise_31001` | Must supply group_id or user_id |
| 31002 | `err_either_perm_set_or_perm` | `error.raise_31002` | Must supply perm_set or permission |
| 31003 | `err_either_perm_id_or_code` | `error.raise_31003` | Must supply permission_id or code |
| 31004 | `err_either_mapping_id_or_role` | `error.raise_31004` | Must supply mapping_id or role |
| 31010 | `err_event_code_is_system` | `error.raise_31010` | Cannot modify system event code |
| 31011 | `err_event_code_not_found` | `error.raise_31011` | Event code does not exist |
| 31012 | `err_event_category_not_empty` | `error.raise_31012` | Category still has event codes |
| 31013 | `err_event_id_out_of_range` | `error.raise_31013` | Event ID outside category range |
| 31014 | `err_event_category_not_found` | `error.raise_31014` | Event category does not exist |

## Permissions (32001 — 32999)

| Code | Name | Raised by | Meaning |
|---|---|---|---|
| 32001 | `err_no_permission` | `error.raise_32001` | Caller lacks the required permission |
| 32002 | `err_permission_not_found` | `error.raise_32002` | Permission does not exist |
| 32003 | `err_permission_not_assignable` | `error.raise_32003` | Permission cannot be assigned |
| 32004 | `err_perm_set_not_found` | `error.raise_32004` | Permission set does not exist |
| 32005 | `err_perm_set_not_assignable` | `error.raise_32005` | Permission set cannot be assigned |
| 32006 | `err_perm_set_wrong_tenant` | `error.raise_32006` | Permission set belongs to another tenant |
| 32007 | `err_parent_permission_not_found` | `error.raise_32007` | Parent permission missing |
| 32008 | `err_some_perms_not_assignable` | `error.raise_32008` | Some permissions in the batch are not assignable |
| 32009 | `err_permission_assignment_not_found` | `error.raise_32009` | Permission assignment does not exist in the tenant (since v2.1) |

## User / Identity / Group (33001 — 33999)

| Code | Name | Raised by | Meaning |
|---|---|---|---|
| 33001 | `err_user_not_found` | `error.raise_33001` | User does not exist |
| 33002 | `err_user_is_system` | `error.raise_33002` | Cannot modify the system user |
| 33003 | `err_user_not_active` | `error.raise_33003` | User is disabled |
| 33004 | `err_user_locked` | `error.raise_33004` | User is locked |
| 33005 | `err_user_cannot_login` | `error.raise_33005` | User not permitted to log in |
| 33006 | `err_user_no_email_provider` | `error.raise_33006` | No email provider for user |
| 33007 | `err_identity_already_used` | `error.raise_33007` | Identity already linked to another user |
| 33008 | `err_identity_not_active` | `error.raise_33008` | Identity is disabled |
| 33009 | `err_identity_not_found` | `error.raise_33009` | Identity does not exist |
| 33010 | `err_provider_not_active` | `error.raise_33010` | Identity provider is disabled |
| 33011 | `err_group_not_found` | `error.raise_33011` | User group does not exist |
| 33012 | `err_group_not_active` | `error.raise_33012` | User group is disabled |
| 33013 | `err_group_not_assignable` | `error.raise_33013` | User group cannot be assigned |
| 33014 | `err_group_is_system` | `error.raise_33014` | Cannot modify a system group |
| 33015 | `err_not_owner` | `error.raise_33015` | Caller is not the owner |
| 33016 | `err_provider_no_group_mapping` | `error.raise_33016` | Provider does not allow group mapping |
| 33017 | `err_provider_no_group_sync` | `error.raise_33017` | Provider does not allow group sync |
| 33018 | `err_user_blacklisted` | `error.raise_33018` | User is blacklisted |
| 33019 | `err_identity_blacklisted` | `error.raise_33019` | Identity is blacklisted |
| 33020 | `err_user_not_resolvable` | `error.raise_33020` | User identifier could not be resolved |
| 33021 | `err_group_not_resolvable` | `error.raise_33021` | Group identifier could not be resolved |
| 33022 | `err_group_mapping_not_found` | `error.raise_33022` | Group mapping does not exist in the tenant (since v2.1) |
| 33023 | `err_group_mapping_already_exists` | `error.raise_33023` | Group already has this mapping (since v2.1) |

## Tenant (34001 — 34999)

| Code | Name | Raised by | Meaning |
|---|---|---|---|
| 34001 | `err_no_tenant_access` | `error.raise_34001` | User has no access to tenant |
| 34002 | `err_cross_tenant_requires_admin` | `error.raise_34002` | Cross-tenant operation requires admin tenant (tenant_id = 1) |
| 34003 | `err_tenant_not_resolvable` | `error.raise_34003` | Tenant identifier could not be resolved |

## Resource access / roles (35001 — 35999)

| Code | Name | Raised by | Meaning |
|---|---|---|---|
| 35001 | `err_no_resource_access` | `error.raise_35001` | User has no access to the resource |
| 35002 | `err_resource_grant_no_target` | `error.raise_35002` | Grant target (user/group) missing |
| 35003 | `err_resource_type_not_found` | `error.raise_35003` | Resource type does not exist |
| 35004 | `err_resource_access_flag_not_found` | `error.raise_35004` | Access flag does not exist |
| 35005 | `err_resource_id_invalid` | inline in `unsecure.validate_resource_id` | `resource_id` contains a key not in the type's `key_schema` |
| 35006 | `err_resource_flag_not_valid` | inline in `unsecure.validate_access_flags_for_type` | Flag not valid for this resource type |
| 35007 | `err_resource_role_not_found` | inline in `unsecure.validate_resource_role` | Resource role does not exist |
| 35008 | `err_resource_role_invalid_flag` | inline in `043_tables_resource_roles.sql` | Role can't include this flag for the type |
| 35009 | `err_resource_role_type_mismatch` | inline in `043_tables_resource_roles.sql` | Role defined for one type, assigned on another |
| 35010 | `err_resource_identifier_required` | inline in `unsecure.validate_resource_identifier` | Neither `_resource_id` (non-empty) nor `_resource_path` was supplied. Enforced on all read and write paths; runs before the system-user / owner shortcuts |

## Token config (36001 — 36999)

| Code | Name | Raised by | Meaning |
|---|---|---|---|
| 36001 | `err_token_type_not_found` | `error.raise_36001` | Token type does not exist |
| 36002 | `err_token_type_is_system` | `error.raise_36002` | Token type is system, cannot modify/delete |

## Language / Translation (37001 — 37999)

| Code | Name | Raised by | Meaning |
|---|---|---|---|
| 37001 | `err_language_not_found` | `error.raise_37001` | Language does not exist |
| 37002 | `err_translation_not_found` | `error.raise_37002` | Translation does not exist |

## MFA (38001 — 38999)

| Code | Name | Raised by | Meaning |
|---|---|---|---|
| 38001 | `err_mfa_already_enrolled` | `error.raise_38001` | MFA already enrolled |
| 38002 | `err_mfa_not_enrolled` | `error.raise_38002` | MFA not enrolled |
| 38003 | `err_mfa_not_confirmed` | `error.raise_38003` | MFA not confirmed |
| 38004 | `err_mfa_invalid_code` | `error.raise_38004` | MFA code is invalid |
| 38005 | `err_mfa_required` | `error.raise_38005` | MFA required for this operation |
| 38006 | `err_mfa_type_not_found` | `error.raise_38006` | MFA type does not exist |
| 38007 | `err_mfa_policy_not_found` | `error.raise_38007` | MFA policy does not exist |

## Invitation (39001 — 39999)

| Code | Name | Raised by | Meaning |
|---|---|---|---|
| 39001 | `err_invitation_not_found` | `error.raise_39001` | Invitation does not exist |
| 39002 | `err_invitation_not_pending` | `error.raise_39002` | Invitation not in pending state |
| 39003 | `err_invitation_expired` | `error.raise_39003` | Invitation has expired |
| 39004 | `err_invitation_action_not_found` | `error.raise_39004` | Invitation action does not exist |
| 39005 | `err_invitation_action_not_pending` | `error.raise_39005` | Action not in pending/processing state |
| 39006 | `err_invitation_template_not_found` | `error.raise_39006` | Template does not exist or is inactive |

---

## Catching errors

```sql
do $$
begin
    perform auth.has_resource_access(1001, 'corr', 'document', '{"id": 500}'::jsonb);
exception
    when sqlstate '35001' then
        raise notice 'No access to resource';
    when sqlstate '35010' then
        raise notice 'Caller bug: must supply resource_id or resource_path';
end;
$$;
```

## Custom codes

Application code should use the `50000+` range. Register them with `public.create_event_category` and `public.create_event_code`. System codes (`is_system = true`) cannot be modified or deleted.
