# PostgreSQL Permissions Model

> **Status: experimental.** The current v2 line (update scripts `048`–`073`, versions 2.1–2.26) is still
> being audited and redesigned. Function signatures, permissions and behaviour may change without notice,
> so don't rely on it in production yet. `CHANGELOG.md` and `client-library-notes.md` list what changed.

A comprehensive PostgreSQL database model for multi-tenant user/group/permissions management with hierarchical permissions, permission sets, and flexible identity provider integration.

## Overview

This is a standalone PostgreSQL framework that provides complete tenant/user/group/permissions management for any PostgreSQL project. Earlier versions are used in many real-world projects, both big and small.

## Key Features

- **Multi-tenancy** with isolated permissions and data (tenant 1 reserved as admin tenant for cross-tenant access)
- **Hierarchical permissions** using PostgreSQL ltree (e.g., `users.create_user.admin_level`)
- **Flexible group types**: Internal, External (mapped to identity providers), and Hybrid
- **Identity provider integration**: Works with any provider (Windows Auth, AzureAD, Google, Facebook, KeyCloak, LDAP, etc.)
- **Permission sets** for role-based access control
- **Resource-level ACL** for per-resource access control (grants, denies, group inheritance)
- **Resource roles** — named flag bundles (e.g., "Editor" = read+write+delete) assigned to users/groups on resources, expanding at check time for instant redefinition
- **Language & translation** with context-aware multi-field support, materialized view for reads, full-text and accent-insensitive search
- **API key management** with technical user pattern
- **Comprehensive audit logging** with multi-key journal entries and event categories
- **App bootstrapping** with idempotent ensure functions and optional `_is_final_state` declarative sync
- **Auto-lockout** on repeated login failures with configurable threshold and time window
- **Multi-factor authentication (TOTP)** with two-step enrollment, recovery codes, challenge/verify flow, recovery reset, and policy-based enforcement
- **Invitation system** with phases, conditions, templates, payload schema resolution, and backend/external action orchestration
- **User blacklist** for blocking re-creation of deleted/banned users (username + provider identity)
- **Permission caching** for performance with automatic invalidation
- **Real-time notifications** via PostgreSQL LISTEN/NOTIFY for permission changes
- **Built-in search/paging** with unified `_search_criteria jsonb` parameter across all search functions

## Quick Start

### Setup
```powershell
# Full database setup (recreate, restore, and update)
./debee.ps1 -Operations fullService

# Or individual operations
./debee.ps1 -Operations recreateDatabase
./debee.ps1 -Operations updateDatabase
```

### Configuration
Configure connection in `debee.env`:
```
PGHOST=localhost
PGPORT=5432
PGUSER=postgres
PGPASSWORD=your_password
DBDESTDB=your_database_name
```

### Running SQL
Use debee's `execSql` operation:
```powershell
./debee.ps1 -Operations execSql -Sql "SELECT * FROM auth.user_info;"   # Inline SQL
./debee.ps1 -Operations execSql -SqlFile script.sql                    # Run file
./debee.ps1 -Operations execSql                                        # Interactive psql
```

### Running Tests
```powershell
make test                      # Run all tests
make test FILTER=resource      # Run filtered subset
./debee.ps1 -Operations runTests                          # Direct debee call
./debee.ps1 -Operations runTests -TestFilter provider     # Filtered
```

### Basic Usage
```sql
-- Check user permission (throws exception if denied)
perform auth.has_permission(_tenant_id, _user_id, 'orders.cancel_order');

-- Silent permission check
if auth.has_permission(_tenant_id, _user_id, 'orders.view', _throw_err := false) then
    -- user has permission
end if;

-- Create permission
select auth.create_permission_by_path('orders.cancel_order', 'Cancel Order');

-- Assign permission to user
select auth.assign_permission(_created_by, _user_id, _tenant_id, _target_user_id, null, 'orders.cancel_order');

-- Search users with pagination
select * from auth.search_users(
    _user_id := 1,
    _search_text := 'john',
    _is_active := true,
    _page := 1,
    _page_size := 20,
    _tenant_id := 1
);

-- Search groups with member counts
select * from auth.search_user_groups(1, 'admin', _is_active := true);

-- Search permissions by parent
select * from auth.search_permissions(1, null, _parent_code := 'users');
```

### App Bootstrapping (Ensure Functions)

Idempotent bulk-create functions for application startup. Call them every boot — they create what's missing, skip what exists, and optionally remove what's no longer defined.

```sql
-- Define permissions (safe to call every startup)
select * from auth.ensure_permissions('app', 1, null, '[
    {"title": "Documents", "is_assignable": false},
    {"title": "Read documents", "parent_code": "documents"},
    {"title": "Write documents", "parent_code": "documents"}
]', 'my_app');

-- Define permission sets with their permissions
select * from auth.ensure_perm_sets('app', 1, null, '[
    {"title": "Document Viewer", "permissions": ["documents.read_documents"]},
    {"title": "Document Editor", "permissions": ["documents.read_documents", "documents.write_documents"]}
]', 'my_app');

-- Define groups
select * from auth.ensure_user_groups('app', 1, null, '[
    {"title": "Document Editors"},
    {"title": "Document Viewers", "is_external": true}
]', 1, 'my_app');

-- Define group mappings (by title or ID)
select * from auth.ensure_user_group_mappings('app', 1, null, '[
    {"user_group_title": "Document Viewers", "provider_code": "azure_ad",
     "mapped_object_id": "aad-group-guid", "mapped_object_name": "Corp Viewers"}
]');
```

**Final state sync** — pass `_is_final_state := true` to make the input the complete definition. Items with the same `_source` not in the input are removed:

```sql
-- Remove "Write documents" on next deploy — just omit it
select * from auth.ensure_permissions('app', 1, null, '[
    {"title": "Documents", "is_assignable": false},
    {"title": "Read documents", "parent_code": "documents"}
]', 'my_app', _is_final_state := true);
```

The `_source` parameter scopes deletions — each module manages only its own items without affecting others.

## Architecture

### Core Components
- **`auth.user_info`** - Core user data
- **`auth.user_identity`** - Multiple identity provider support per user
- **`auth.user_data`** - Profile fields + three jsonb columns (`settings`, `preferences`, `custom_data`) with partial merge via `auth.update_user_data`
- **`auth.tenant`** - Multi-tenancy management
- **`auth.user_group`** - Three group types (internal/external/hybrid)
- **`auth.permission`** - Global hierarchical permissions
- **`auth.perm_set`** - Tenant-specific permission collections
- **`auth.resource_access`** - Resource-level ACL (list-partitioned by resource_type)
- **`const.resource_role`** / **`const.resource_role_flag`** - Named flag bundles per resource_type
- **`auth.resource_role_assignment`** - Role grants on resources (list-partitioned by root_type)
- **`auth.user_mfa`** - MFA enrollment state, encrypted secrets, hashed recovery codes
- **`auth.mfa_policy`** - MFA enforcement rules (scope: user > group > tenant > global)
- **`auth.invitation`** - Invitation lifecycle with phases, conditions, and action orchestration
- **`auth.invitation_template`** - Reusable invitation templates with action definitions
- **`auth.user_blacklist`** - Blacklist for deleted/banned user identities
- **`auth.api_key`** - Service authentication with technical users
- **`const.language`** / **`public.translation`** / **`public.mv_translation`** - Language registry, translation storage with context-aware multi-field support, and materialized view for efficient reads
- **`public.journal`** - Audit logging with multi-key support, request context tracking (range-partitioned by month)
- **`auth.user_event`** - Security event audit trail with request context tracking (range-partitioned by month)

### Schema Security Model
- **`public`** & **`auth`** - Always validate permissions
- **`internal`** - For trusted contexts (no permission checks)
- **`unsecure`** - Security system internals only

### Multi-Tenant Data Access (Tenant 1 = Admin Tenant)

Tenant 1 is reserved as the **admin/super tenant**. In single-tenant applications there is no difference — everything runs under tenant 1 and the system behaves as if multi-tenancy doesn't exist. In multi-tenant applications, tenant 1 serves as the admin console with cross-tenant visibility.

Search and get functions that return tenant-scoped data use two tenant parameters:

| Parameter | Purpose |
|-----------|---------|
| `_tenant_id` | Caller's tenant — used for permission checking |
| `_target_tenant_id` | Which tenant's data to query (optional) |

**Permission resolution:**

| Caller's tenant | `_target_tenant_id` | Behavior |
|----------------|---------------------|----------|
| `_tenant_id = 1` | `null` | Admin console — show data from **all tenants** (requires `*.read_all_*` permission) |
| `_tenant_id = 1` | `30` | Admin console — show data from **tenant 30 only** (requires `*.read_all_*` permission) |
| `_tenant_id = 30` | `null` | Regular tenant — show data from **own tenant only** (requires `*.read_*` permission) |
| `_tenant_id = 30` | any value | **Error 34002** — cross-tenant access requires admin tenant |

Each domain has paired permissions — a regular permission for own-tenant access and an "all" variant for cross-tenant access from the admin tenant:

```
users.read_users          -- read users within own tenant
users.read_all_users      -- read users across tenants (admin console only)

invitations.get_invitations       -- list invitations within own tenant
invitations.get_all_invitations   -- list invitations across tenants (admin console only)
```

**Example pattern** used in search/get functions:
```sql
-- Determine effective tenant for filtering
if _target_tenant_id is not null then
    -- cross-tenant: admin console only
    if _tenant_id <> 1 then
        perform error.raise_34002(_tenant_id);
    end if;
    perform auth.has_permission(_user_id, _correlation_id, 'domain.read_all_items', _target_tenant_id);
    __effective_tenant_id := _target_tenant_id;
elsif _tenant_id = 1 then
    perform auth.has_permission(_user_id, _correlation_id, 'domain.read_all_items', _tenant_id);
    __effective_tenant_id := null;  -- null = no tenant filter = all tenants
else
    perform auth.has_permission(_user_id, _correlation_id, 'domain.read_items', _tenant_id);
    __effective_tenant_id := _tenant_id;
end if;
-- Then use __effective_tenant_id in WHERE clause (null = no filter)
```

### Service Accounts

The system ships with dedicated service accounts (IDs 1-999 reserved) so backends never need to use the `system` superuser (user_id:1) at runtime. Each account has only the permissions required for its job.

| ID | Username | Purpose |
|----|----------|---------|
| 1 | `system` | Seed/migration — has `has_permissions` bypass, should not be used at runtime |
| 2 | `svc_registrator` | User registration + email/phone verification token creation |
| 3 | `svc_authenticator` | Login, permission resolution, token validation |
| 4 | `svc_token_manager` | Full token lifecycle (password reset, email verification, etc.) |
| 5 | `svc_api_gateway` | API key validation at gateway/middleware level |
| 6 | `svc_group_syncer` | Background external group member synchronization |
| 800 | `svc_data_processor` | Generic app-level processing (empty perm set — app adds its own) |

All service accounts have `user_type_code = 'service'`, `can_login = false`, `is_system = true`.

**Usage:** pass the appropriate service account's `user_id` instead of `1` when calling `auth.*` functions from your backend:
```sql
-- Before (superuser bypass — no permission check at all)
select auth.has_permission(1, null, 'users.register_user', 1);

-- After (least-privilege — actually validates the permission)
select auth.has_permission(2, null, 'users.register_user', 1);
```

The `svc_data_processor` (ID 800) is the recommended default for application-specific operations. Add permissions to its `svc_data_processor_permissions` perm set as needed.

### Human Admin Permission Sets

Composable permission sets for human administrators. Each set covers a specific administrative domain — assign one or combine several for composite roles.

| Permission Set | Domain | Key Permissions |
|---------------|--------|-----------------|
| `User manager` | User CRUD + audit | `users`, `authentication.read_user_events` |
| `Group manager` | Groups & membership | `groups` |
| `Permission manager` | Permissions & perm sets | `permissions` |
| `Provider manager` | Identity providers | `providers` |
| `Token manager` | Token lifecycle & config | `tokens.*`, `token_configuration` |
| `Api key manager` | API key CRUD | `api_keys` |
| `Auditor` | Read-only audit access | `journal`, `authentication.read_user_events`, read-only entity access |
| `Full admin` | Everything combined | All admin permissions including `journal.purge_journal` |

All sets include `journal.read_journal` and `journal.get_payload` for audit visibility (except Auditor which has the full `journal` parent permission).

**Built-in group:** "Full admins" (group ID 3) has the `full_admin` perm set assigned. Add users to this group for complete administrative access:

```sql
-- Add user to Full admins group
select auth.create_user_group_member('admin', 1, null, 3, _target_user_id := 1001);

-- Or assign individual role perm sets to a user
select auth.assign_permission('admin', 1, null, 1, null, 1001, null, 'user_manager');
select auth.assign_permission('admin', 1, null, 1, null, 1001, null, 'group_manager');
```

## Journal / Audit Logging

The `public.journal` table provides comprehensive audit logging with multi-key support. The journal is shared across all modules — the permissions system logs its own events here, and applications can register custom event codes and create their own journal entries alongside the core ones.

### Creating Journal Entries

```sql
-- Using event code name (recommended)
select * from create_journal_message(
    'admin',           -- created_by
    1,                 -- user_id
    'user_created',    -- event code (text)
    'New user registered',
    _keys := '{"user": 123, "tenant": 1}'::jsonb
);

-- Single entity convenience
select * from create_journal_message(
    'admin', 1, 'group_created', 'Group created',
    'group', 456  -- entity_type, entity_id
);

-- With request context (stored in journal.request_context column)
select * from create_journal_message_for_entity(
    'admin', 1, 'corr-123',
    10001, 'user', 123,
    '{"username": "john"}'::jsonb,
    1,
    _request_context := '{"ip_address": "192.168.1.1", "user_agent": "Mozilla/5.0"}'::jsonb
);
```

### Searching Journal

```sql
-- Search by event category (for UI filtering like "show all user events")
SELECT * FROM search_journal(
    _user_id := 1,
    _event_category := 'user_event'
);

-- Search by entity keys
SELECT * FROM search_journal(
    _user_id := 1,
    _keys_criteria := '{"order": 3}'::jsonb
);

-- Full-text search with filters
SELECT * FROM search_journal(
    _user_id := 1,
    _search_text := 'password',
    _event_category := 'user_event',
    _from := now() - interval '7 days'
);
```

### Event Categories

| Category | Description |
|----------|-------------|
| `user_event` | User lifecycle, login, password changes |
| `tenant_event` | Tenant management |
| `permission_event` | Permission assignments |
| `group_event` | Group membership changes |
| `apikey_event` | API key operations |
| `token_event` | Token lifecycle |
| `provider_event` | Provider lifecycle |
| `maintenance_event` | System maintenance operations |
| `resource_event` | Resource access (ACL) operations |
| `language_event` | Language CRUD |
| `translation_event` | Translation CRUD and copy operations |
| `invitation_event` | Invitation lifecycle, actions, and templates |

### Audit Summary Queries

Higher-level query functions for common audit needs:

```sql
-- Unified audit trail for a specific user (combines journal + user_event)
select * from auth.get_user_audit_trail(
    _user_id := 1,
    _target_user_id := 1001,
    _from := now() - interval '30 days',
    _page := 1,
    _page_size := 20
);

-- Security events across the system (failed logins, lockouts, permission denials)
select * from auth.get_security_events(
    _user_id := 1,
    _from := now() - interval '7 days'
);
```

### Request Context

All security-relevant functions (user management, token operations, API key validation) accept an optional `_request_context jsonb` parameter. This stores caller metadata (IP address, user agent, origin, device ID, etc.) alongside the event and journal records without requiring schema changes when new fields are needed.

```sql
-- Pass request context to any security function
select auth.enable_user('admin', 1, 'corr-123', 42,
    _request_context := jsonb_build_object(
        'ip_address', '192.168.1.1',
        'user_agent', 'Mozilla/5.0',
        'origin', 'https://app.example.com',
        'device_id', 'abc-123'
    ));

-- Context is stored on auth.user_event.request_context, auth.token.request_context,
-- and public.journal.request_context — queryable with standard jsonb operators
select request_context ->> 'ip_address' as ip
from auth.user_event
where target_user_id = 42;
```

### Partitioning & Data Retention

Both `public.journal` and `auth.user_event` are range-partitioned by `created_at` (monthly). This enables:

- **Partition pruning** — date-filtered queries only scan relevant monthly partitions
- **Instant purge** — old partitions are detached and dropped instead of row-by-row `DELETE`
- **INSERT performance** — writes target the current month's partition (smaller indexes)

Configuration in `const.sys_param` (see [System Parameters](#system-parameters) for the full reference):

```sql
-- Purge data older than configured retention (requires journal.purge_journal permission)
-- Drops old partitions + cleans default partition + pre-creates future partitions
select * from public.purge_audit_data('admin', 1, null);

-- Purge with explicit retention override
select * from public.purge_audit_data('admin', 1, null, _older_than_days := 90);

-- Pre-create future partitions manually (also called automatically by purge)
select unsecure.ensure_audit_partitions(3);
```

The purge itself is journaled (event 17001 `audit_data_purged`) for accountability.

### Storage Modes (Offloading to External Systems)

For large deployments where storing all journal/event data in PostgreSQL is unnecessary, the system supports offloading data to an external store (e.g., ClickHouse) via PostgreSQL's LISTEN/NOTIFY. Storage mode is controlled independently for journal and user events:

| Mode | Behavior |
|------|----------|
| `local` | INSERT into PostgreSQL only (default — no behavior change) |
| `notify` | Fire `pg_notify` only, skip INSERT — an external listener captures the data |
| `both` | INSERT into PostgreSQL AND fire `pg_notify` |

```sql
-- Switch journal to notify-only (stop storing in PostgreSQL)
select auth.update_sys_param(1, 'journal', 'storage_mode', 'notify');

-- Switch user events to both (store locally + notify external)
select auth.update_sys_param(1, 'user_event', 'storage_mode', 'both');

-- Read current storage mode
select (auth.get_sys_param('journal', 'storage_mode')).text_value;
```

**Backend listener setup:**
```js
// Dedicated connection (not from pool — PgBouncer transaction mode doesn't support LISTEN)
await client.query('LISTEN journal_events');
await client.query('LISTEN user_events');

client.on('notification', (msg) => {
    const event = JSON.parse(msg.payload);
    if (event.truncated) {
        // Large fields were stripped — handle accordingly
    }
    clickhouse.insert(msg.channel, event);
});
```

**Notify channels:** `journal_events` and `user_events` (separate from `permission_changes`)

**Payload truncation:** pg_notify has an 8000 byte limit. If a payload exceeds ~7900 bytes, large fields (`data_payload`/`request_context` for journal, `event_data`/`request_context` for user events) are stripped and `"truncated": true` is added.

**Note:** When mode is `notify`, search/query functions (`search_journal`, `get_journal_entry`, `search_user_events`, etc.) return empty results since data is not stored in PostgreSQL. The application should query the external store directly for audit data.

## System Parameters

Runtime configuration is stored in `const.sys_param` and managed via `auth.get_sys_param()` / `auth.update_sys_param()`. The setter is restricted to user_id = 1 (system user) — intended for app startup.

```sql
-- Read a parameter
select (auth.get_sys_param('journal', 'level')).text_value;

-- Update a parameter (system user only)
select auth.update_sys_param(1, 'journal', 'level', 'all');
```

### Parameter Reference

| group_code | code | default | type | description |
|------------|------|---------|------|-------------|
| `journal` | `level` | `update` | text | Journal logging verbosity. `all` = log everything including reads, `update` = state-changing operations only, `none` = disable journaling |
| `journal` | `retention_days` | `365` | text (cast to int) | How many days of journal entries to keep. Used by `purge_audit_data()` |
| `journal` | `storage_mode` | `local` | text | Where journal data goes. `local` = INSERT only, `notify` = pg_notify only, `both` = INSERT + pg_notify |
| `user_event` | `retention_days` | `365` | text (cast to int) | How many days of user events to keep. Used by `purge_audit_data()` |
| `user_event` | `storage_mode` | `local` | text | Where user event data goes. Same modes as journal |
| `partition` | `months_ahead` | `3` | number | How many future monthly partitions to pre-create for journal and user_event tables |
| `login_lockout` | `max_failed_attempts` | `5` | number | Number of failed login attempts before auto-lock |
| `login_lockout` | `window_minutes` | `15` | number | Time window in minutes for counting failed login attempts |
| `auth` | `perm_cache_timeout_in_s` | `300` (fallback) | number | Permission cache TTL in seconds. Not seeded — uses hardcoded fallback if missing |

## Real-Time Permission Notifications

The system uses PostgreSQL's built-in LISTEN/NOTIFY to push permission change events to backends in real-time. When any permission-relevant mutation occurs (assignment, group membership, user status, etc.), a JSON notification is sent on the `permission_changes` channel.

### Backend Setup
```js
// Dedicated connection (not from pool — PgBouncer transaction mode doesn't support LISTEN)
await client.query('LISTEN permission_changes');

client.on('notification', (msg) => {
    const payload = JSON.parse(msg.payload);
    // payload: { event, tenant_id, target_type, target_id, detail, at }
    broadcastToAffectedClients(payload, { type: 'REFETCH_PERMISSIONS' });
});
```

### Notification Events

| Event | Trigger | target_type |
|-------|---------|-------------|
| `permission_assigned` / `permission_unassigned` | Permission or perm_set assigned to user/group | `user` or `group` |
| `perm_set_permissions_added` / `perm_set_permissions_removed` | Permissions added/removed from a set | `perm_set` |
| `group_member_added` / `group_member_removed` | User added/removed from group | `user` |
| `group_disabled` / `group_enabled` / `group_deleted` | Group status change | `group` |
| `group_mapping_created` / `group_mapping_deleted` | External group mapping change | `group` |
| `user_disabled` / `user_locked` / `user_deleted` | User status change | `user` |
| `owner_created` / `owner_deleted` | Ownership change | `user` |
| `provider_disabled` / `provider_deleted` | Identity provider change | `provider` |
| `tenant_deleted` | Tenant removal | `tenant` |

### Resolving Affected Users

Notifications carry IDs, not user lists. After receiving a notification, query the matching resolution view:

```sql
-- Group event → which users to notify?
SELECT user_id FROM auth.notify_group_users WHERE user_group_id = $1;

-- Perm set changed → which users to notify?
SELECT user_id FROM auth.notify_perm_set_users WHERE perm_set_id = $1;

-- Permission assignability changed → which users to notify?
SELECT user_id FROM auth.notify_permission_users WHERE permission_id = $1;

-- Provider disabled/deleted → which users to notify?
SELECT user_id FROM auth.notify_provider_users WHERE provider_code = $1;

-- Tenant deleted → which users to notify?
SELECT user_id FROM auth.notify_tenant_users WHERE tenant_id = $1;
```

For `target_type = 'user'` events (user status changes, group member add/remove, owner changes), the `target_id` is the user_id directly — no view needed.

Notifications are delivered after COMMIT (never for rolled-back transactions) and are fire-and-forget — cache invalidation handles correctness, notifications handle client freshness.

## Group Mapping Strategy

Supports three group types for flexible identity provider integration:

- **Internal Groups**: Traditional membership stored in database
- **External Groups**: Membership determined by identity provider mappings (no local storage)
- **Hybrid Groups**: Combination of both approaches

Example: User logs in with AzureAD groups → System maps external groups to internal permissions → User gets permissions without being explicitly added as member.

## Identity Providers

Providers represent external authentication systems (AzureAD, Google, LDAP, email, etc.). Each provider has a `code`, `name`, and `is_active` flag.

```sql
-- Create provider (requires providers.create_provider permission)
select * from auth.create_provider('admin', 1, null, 'google', 'Google authentication');

-- Idempotent: create if missing, return existing if found
select * from auth.ensure_provider('admin', 1, null, 'google', 'Google authentication');
-- Returns: __provider_id, __is_new (true on first call, false on subsequent)

-- Enable/disable
select * from auth.enable_provider('admin', 1, null, 'google');
select * from auth.disable_provider('admin', 1, null, 'google');
```

## Documentation

- **[CLAUDE.md](./CLAUDE.md)** - Developer guide for Claude Code
- **[resource-access.md](./resource-access.md)** - Resource-level ACL system documentation
- **[CHANGELOG.md](./CHANGELOG.md)** - Version history
- **Complete Documentation** - [postgresql-permissions-model-docs](../postgresql-permissions-model-docs) (comprehensive documentation project)
- **[functions.md](./functions.md)** - Function reference
- **[features.md](./features.md)** - Feature list

## Integration

### With Application Libraries
- [`keen-auth-permissions`](https://github.com/KeenMate/keen-auth-permissions) — Elixir library with application-level wrappers around these SQL functions
- C# library — planned

### Direct SQL Integration
Always use fully qualified schema names to avoid search_path issues:
```sql
-- Good
select auth.has_permission(_tenant_id, _user_id, 'permission.code');

-- Avoid (can cause "cannot find function" errors)
select has_permission(_tenant_id, _user_id, 'permission.code');
```

## Version Management

Simple version tracking with `public.__version` table:
```sql
select * from public.start_version_update('1.0', 'Initial version');
-- migration content
select * from public.stop_version_update('1.0');
```

## Requirements

- PostgreSQL with extensions: `ltree`, `uuid-ossp`, `unaccent`, `pg_trgm`
- PowerShell (for setup scripts)

## License

[MIT License](./LICENSE)

## Event and Error Codes

The system uses structured event/error codes organized by category. Codes are stored in `const.event_code` table.

### Code Ranges

| Range | Category | Description |
|-------|----------|-------------|
| 10001-10999 | User Events | Login, logout, password, identity management |
| 11001-11999 | Tenant Events | Tenant lifecycle and user access |
| 12001-12999 | Permission Events | Permission and permission set management |
| 13001-13999 | Group Events | Group membership and mappings |
| 14001-14999 | API Key Events | API key lifecycle and validation |
| 15001-15999 | Token Events | Token lifecycle |
| 16001-16999 | Provider Events | Provider lifecycle |
| 17001-17999 | Maintenance Events | System maintenance operations |
| 18001-18999 | Resource Access Events | Resource type and ACL operations |
| 19001-19999 | Token Config Events | Token configuration changes |
| 20001-20999 | Language Events | Language CRUD |
| 21001-21999 | Translation Events | Translation CRUD and copy operations |
| 22001-22999 | Invitation Events | Invitation lifecycle, actions, and templates |
| 30001-30999 | Security Errors | Authentication and token errors |
| 31001-31999 | Validation Errors | Missing required parameters |
| 32001-32999 | Permission Errors | Permission not found, not assignable |
| 33001-33999 | User/Group Errors | Entity not found, not active, system entity |
| 34001-34999 | Tenant Errors | Tenant access errors |
| 35001-35999 | Resource Access Errors | Resource ACL errors |
| 36001-36999 | Token Config Errors | Token configuration errors |
| 37001-37999 | Language/Translation Errors | Language and translation errors |
| 38001-38999 | MFA Errors | Multi-factor authentication errors |
| 39001-39999 | Invitation Errors | Invitation lifecycle errors |
| 50000+ | Reserved | Application-specific events and errors |

### Informational Events (10xxx-21xxx)

#### User Events (10001-10999)

| Code | Event | Description |
|------|-------|-------------|
| 10001 | user_created | New user account was created |
| 10002 | user_updated | User account was updated |
| 10003 | user_deleted | User account was deleted |
| 10004 | user_enabled | User account was enabled |
| 10005 | user_disabled | User account was disabled |
| 10006 | user_locked | User account was locked |
| 10007 | user_unlocked | User account was unlocked |
| 10010 | user_logged_in | User successfully logged in |
| 10011 | user_logged_out | User logged out |
| 10012 | user_login_failed | User login attempt failed |
| 10020 | password_changed | User password was changed |
| 10021 | password_reset_requested | Password reset was requested |
| 10022 | password_reset_completed | Password reset was completed |
| 10030 | identity_created | User identity was created |
| 10031 | identity_updated | User identity was updated |
| 10032 | identity_deleted | User identity was deleted |
| 10033 | identity_enabled | User identity was enabled |
| 10034 | identity_disabled | User identity was disabled |
| 10040 | email_verified | User email was verified |
| 10041 | phone_verified | User phone was verified |
| 10050 | mfa_enabled | Multi-factor authentication was enabled |
| 10051 | mfa_disabled | Multi-factor authentication was disabled |
| 10070 | external_data_updated | User data was updated from external source |
| 10080 | user_blacklisted | User was added to blacklist |
| 10081 | user_unblacklisted | User was removed from blacklist |
| 10082 | user_creation_blocked | User creation was blocked by blacklist |
| 10083 | user_auto_locked | User auto-locked after too many failed login attempts |
| 10090 | mfa_enrolled | MFA enrollment was initiated |
| 10091 | mfa_enrollment_confirmed | MFA enrollment was confirmed with a valid code |
| 10092 | mfa_challenge_created | MFA challenge token was created |
| 10093 | mfa_challenge_passed | MFA challenge was successfully verified |
| 10094 | mfa_recovery_used | MFA recovery code was used to pass challenge |
| 10095 | mfa_policy_created | MFA policy rule was created |
| 10096 | mfa_policy_deleted | MFA policy rule was deleted |
| 10097 | mfa_recovery_reset | MFA recovery codes were regenerated |

#### Tenant Events (11001-11999)

| Code | Event | Description |
|------|-------|-------------|
| 11001 | tenant_created | New tenant was created |
| 11002 | tenant_updated | Tenant was updated |
| 11003 | tenant_deleted | Tenant was deleted |
| 11010 | tenant_user_added | User was added to tenant |
| 11011 | tenant_user_removed | User was removed from tenant |

#### Permission Events (12001-12999)

| Code | Event | Description |
|------|-------|-------------|
| 12001 | permission_created | New permission was created |
| 12002 | permission_updated | Permission was updated |
| 12003 | permission_deleted | Permission was deleted |
| 12010 | permission_assigned | Permission was assigned |
| 12011 | permission_revoked | Permission was revoked |
| 12020 | perm_set_created | New permission set was created |
| 12021 | perm_set_updated | Permission set was updated |
| 12022 | perm_set_deleted | Permission set was deleted |
| 12023 | perm_set_assigned | Permission set was assigned |
| 12024 | perm_set_revoked | Permission set was revoked |

#### Group Events (13001-13999)

| Code | Event | Description |
|------|-------|-------------|
| 13001 | group_created | New group was created |
| 13002 | group_updated | Group was updated |
| 13003 | group_deleted | Group was deleted |
| 13010 | group_member_added | Member was added to group |
| 13011 | group_member_removed | Member was removed from group |
| 13020 | group_mapping_created | Group mapping was created |
| 13021 | group_mapping_deleted | Group mapping was deleted |
| 13030 | group_members_synced | External group members synchronized from provider |

#### API Key Events (14001-14999)

| Code | Event | Description |
|------|-------|-------------|
| 14001 | apikey_created | New API key was created |
| 14002 | apikey_updated | API key was updated |
| 14003 | apikey_deleted | API key was deleted |
| 14010 | apikey_validated | API key was validated |
| 14011 | apikey_validation_failed | API key validation failed |

#### Token Events (15001-15999)

| Code | Event | Description |
|------|-------|-------------|
| 15001 | token_created | New token was created |
| 15002 | token_used | Token was used |
| 15003 | token_expired | Token expired |
| 15004 | token_failed | Token validation failed |

#### Provider Events (16001-16999)

| Code | Event | Description |
|------|-------|-------------|
| 16001 | provider_created | New provider was created |
| 16002 | provider_updated | Provider was updated |
| 16003 | provider_deleted | Provider was deleted |
| 16004 | provider_enabled | Provider was enabled |
| 16005 | provider_disabled | Provider was disabled |

#### Maintenance Events (17001-17999)

| Code | Event | Description |
|------|-------|-------------|
| 17001 | audit_data_purged | Old audit data was purged |

#### Resource Access Events (18001-18999)

| Code | Event | Description |
|------|-------|-------------|
| 18001 | resource_type_created | New resource type was registered |
| 18002 | resource_type_updated | Resource type was updated |
| 18003 | resource_role_created | New resource role was registered |
| 18004 | resource_role_updated | Resource role definition or flags changed |
| 18005 | resource_role_deleted | Resource role was deleted |
| 18010 | resource_access_granted | Resource access was granted |
| 18011 | resource_access_revoked | Resource access was revoked |
| 18012 | resource_access_denied | Resource access was denied |
| 18013 | resource_access_bulk_revoked | All resource access was revoked for a resource |
| 18020 | resource_role_assigned | Resource role assigned to user or group |
| 18021 | resource_role_revoked | Resource role revoked from user or group |

#### Language Events (20001-20999)

| Code | Event | Description |
|------|-------|-------------|
| 20001 | language_created | New language was created |
| 20002 | language_updated | Language was updated |
| 20003 | language_deleted | Language was deleted |

#### Translation Events (21001-21999)

| Code | Event | Description |
|------|-------|-------------|
| 21001 | translation_created | New translation was created |
| 21002 | translation_updated | Translation was updated |
| 21003 | translation_deleted | Translation was deleted |
| 21004 | translations_copied | Translations were copied between languages |

#### Invitation Events (22001-22999)

| Code | Event | Description |
|------|-------|-------------|
| 22001 | invitation_created | New invitation was created |
| 22002 | invitation_accepted | Invitation was accepted by the recipient |
| 22003 | invitation_rejected | Invitation was rejected by the recipient |
| 22004 | invitation_revoked | Invitation was revoked by the inviter |
| 22005 | invitation_expired | Invitation expired without response |
| 22006 | invitation_action_completed | An invitation action was completed |
| 22007 | invitation_action_failed | An invitation action failed |
| 22008 | invitation_completed | All invitation actions were completed |
| 22009 | invitation_failed | Invitation processing failed due to a required action failure |
| 22010 | invitation_template_created | Invitation template was created |
| 22011 | invitation_template_updated | Invitation template was updated |
| 22012 | invitation_template_deleted | Invitation template was deleted |

### Error Codes (30xxx-39xxx)

#### Security Errors (30001-30999)

| Code | Function | Description |
|------|----------|-------------|
| 30001 | error.raise_30001 | API key/secret combination is not valid |
| 30002 | error.raise_30002 | Token is not valid or has expired |
| 30003 | error.raise_30003 | Token was created for different user |
| 30004 | error.raise_30004 | Token has already been used |
| 30005 | error.raise_30005 | Token does not exist |

#### Validation Errors (31001-31999)

| Code | Function | Description |
|------|----------|-------------|
| 31001 | error.raise_31001 | Either user group or target user id must not be null |
| 31002 | error.raise_31002 | Either permission set code or permission code must not be null |
| 31003 | error.raise_31003 | Either permission id or code must not be null |
| 31004 | error.raise_31004 | Either mapped object id or mapped role must not be empty |

#### Permission Errors (32001-32999)

| Code | Function | Description |
|------|----------|-------------|
| 32001 | error.raise_32001 | User does not have required permission |
| 32002 | error.raise_32002 | Permission does not exist |
| 32003 | error.raise_32003 | Permission is not assignable |
| 32004 | error.raise_32004 | Permission set does not exist |
| 32005 | error.raise_32005 | Permission set is not assignable |
| 32006 | error.raise_32006 | Permission set is not defined in this tenant |
| 32007 | error.raise_32007 | Parent permission does not exist |
| 32008 | error.raise_32008 | Some permissions are not assignable |

#### User/Group Errors (33001-33999)

| Code | Function | Description |
|------|----------|-------------|
| 33001 | error.raise_33001 | User does not exist |
| 33002 | error.raise_33002 | User is a system user |
| 33003 | error.raise_33003 | User is not in active state |
| 33004 | error.raise_33004 | User is locked out |
| 33005 | error.raise_33005 | User is not supposed to log in |
| 33006 | error.raise_33006 | User cannot be ensured for email provider |
| 33007 | error.raise_33007 | User identity is already in use |
| 33008 | error.raise_33008 | User identity is not in active state |
| 33009 | error.raise_33009 | User identity does not exist |
| 33010 | error.raise_33010 | Provider is not in active state |
| 33011 | error.raise_33011 | User group does not exist |
| 33012 | error.raise_33012 | User group is not active |
| 33013 | error.raise_33013 | User group is not assignable or is external |
| 33014 | error.raise_33014 | User group is a system group |
| 33015 | error.raise_33015 | User is not tenant or group owner |
| 33018 | error.raise_33018 | User is blacklisted and cannot be created |
| 33019 | error.raise_33019 | User identity is blacklisted and cannot be created |

#### Tenant Errors (34001-34999)

| Code | Function | Description |
|------|----------|-------------|
| 34001 | error.raise_34001 | User has no access to this tenant |

#### Resource Access Errors (35001-35999)

| Code | Function | Description |
|------|----------|-------------|
| 35001 | error.raise_35001 | User has no access to resource |
| 35002 | error.raise_35002 | Neither user_id nor user_group_id provided |
| 35003 | error.raise_35003 | Resource type not found or inactive |
| 35004 | error.raise_35004 | Access flag not found |
| 35005 | error.raise_35005 | Resource ID missing required key from key_schema |
| 35006 | error.raise_35006 | Access flag not valid for resource type |
| 35007 | error.raise_35007 | Resource role not found or inactive |
| 35008 | error.raise_35008 | Role flag not valid for resource type |
| 35009 | error.raise_35009 | Role resource_type mismatch at assignment |

#### Language/Translation Errors (37001-37999)

| Code | Function | Description |
|------|----------|-------------|
| 37001 | error.raise_37001 | Language does not exist |
| 37002 | error.raise_37002 | Translation does not exist |

#### MFA Errors (38001-38999)

| Code | Function | Description |
|------|----------|-------------|
| 38001 | error.raise_38001 | MFA is already enrolled and confirmed for this type |
| 38002 | error.raise_38002 | MFA is not enrolled for this type |
| 38003 | error.raise_38003 | MFA enrollment is not confirmed |
| 38004 | error.raise_38004 | The provided MFA code is not valid |
| 38005 | error.raise_38005 | MFA verification is required |
| 38006 | error.raise_38006 | MFA type does not exist or is inactive |
| 38007 | error.raise_38007 | MFA policy does not exist |

#### Invitation Errors (39001-39999)

| Code | Function | Description |
|------|----------|-------------|
| 39001 | error.raise_39001 | Invitation does not exist |
| 39002 | error.raise_39002 | Invitation is not in pending state |
| 39003 | error.raise_39003 | Invitation has expired |
| 39004 | error.raise_39004 | Invitation action does not exist |
| 39005 | error.raise_39005 | Invitation action is not in pending or processing state |
| 39006 | error.raise_39006 | Invitation template does not exist or is inactive |

### Legacy Code Mapping (v1 Compatibility)

Old v1 error codes (52xxx) are still supported via aliases. See `016_functions_error.sql` for the complete mapping.


