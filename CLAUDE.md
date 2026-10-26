# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a standalone PostgreSQL database model that provides complete tenant/user/group/permissions management for any PostgreSQL project. It's a self-contained SQL-based framework that gives applications comprehensive handling of multi-tenancy, user management, hierarchical permissions, permission sets, and role-based access control. The separate `../keen-auth-permissions` library is built on top of this database model to provide application-level integration.

## Key Architecture Components

### Database Schema Organization & Security Model
The system uses multiple PostgreSQL schemas with distinct security boundaries:

**Permission-Checked Schemas (always validate permissions):**
- `public` - Application business functions with permission checks (kept clean for app-specific functions)
- `auth` - Security functions with permission checks (same as public, but security-focused)

**No Permission Checks (trusted contexts only):**
- `internal` - Business functions without permission checks (wrapped by public functions or called from secure app context)
- `unsecure` - Security-related internal functions only (NOT for unprotected business logic)

**Utility & Configuration:**
- `helpers` - Utility functions (random strings, code generation, ltree operations)
- `error` - Error handling and exception functions
- `const` - Constants and configuration tables (user types, event types, system parameters)
- `ext` - PostgreSQL extensions (ltree, uuid-ossp, unaccent, pg_trgm)
- `stage` - Staging tables for data imports (e.g., external group members)

**Key Security Principle**:
- `public` and `auth` schemas ALWAYS check permissions (except utility functions like get_app_version)
- `internal` is for business logic that's already permission-checked at a higher level
- `unsecure` is ONLY for security-system internals, never for business functions

### Core Entities
This system manages the complete lifecycle of authorization entities:

**Multi-Tenancy (Tenant 1 = Admin Tenant):**
- **Tenants** (`auth.tenant`) - Multi-tenancy support with isolated permissions and data
- **Tenant 1** is reserved as the admin/super tenant. In single-tenant apps there's no difference. In multi-tenant apps, tenant 1 is the admin console with cross-tenant visibility.
- Search/get functions use `_tenant_id` (caller's tenant for permission checks) + `_target_tenant_id` (which tenant's data to query). If `_tenant_id = 1`, cross-tenant access is allowed with `read_all_*` permissions. If `_tenant_id != 1`, only own-tenant data is returned.
- Each domain has paired permissions: `domain.read_*` (own tenant) + `domain.read_all_*` (cross-tenant from admin).
- **Tenant Users** (`auth.tenant_user`) - Links users to tenants they have access to
- **User Tenant Preferences** (`auth.user_tenant_preference`) - Per-tenant user settings/preferences
- **Ownership** (`auth.owner`) - Tracks tenant owners and group owners

**User Management:**
- **Users** (`auth.user_info`) - Core user data
- **User Identity** (`auth.user_identity`) - Provider-specific identities (Windows GUID, AzureAD UID, etc.)
- **User Data** (`auth.user_data`) - Profile fields + three jsonb columns: `settings`, `preferences`, `custom_data` with partial merge support
- **User Permission Cache** (`auth.user_permission_cache`) - Cached permission calculations for performance

**Groups & Mappings:**
- **Groups** (`auth.user_group`) - Three types: internal, external, and hybrid membership models
- **Group Mappings** (`auth.user_group_mapping`) - Maps external provider groups/roles to internal groups
- **Group Members** (`auth.user_group_member`) - Direct group membership for internal/hybrid groups

**Permissions & Sets:**
- **Permissions** (`auth.permission`) - Global hierarchical permission tree using ltree
- **Permission Sets** (`auth.perm_set`) - Tenant-specific permission collections
- **Permission Set Permissions** (`auth.perm_set_perm`) - Links permissions to permission sets
- **Permission Assignments** (`auth.permission_assignment`) - Assigns permissions/sets to users/groups

**Authentication & Security:**
- **Providers** (`auth.provider`) - External identity provider configurations
- **Tokens** (`auth.token`) - Short-lived authentication tokens
- **API Keys** (`auth.api_key`) - Long-lived service authentication with technical users

**Audit & Logging:**
- **User Events** (`auth.user_event`) - Comprehensive audit log for all security events
- **Journal** (`journal`) - General-purpose journaling/logging table

### Permission Model
The system implements a hierarchical permission model with clear separation between permissions and permission sets:

**Permissions (Global)**:
- Hierarchical structure using PostgreSQL's ltree extension
- Examples: `users`, `users.create_user`, `users.read_users.read_gdpr_protected_data`
- Can have unlimited nesting levels based on application needs
- **Global across all tenants** - same permission structure for everyone

**Permission Sets (Tenant-Specific)**:
- Collections of permissions grouped by role/function
- **Tenant-specific** - each tenant can have different permission sets with different permission combinations
- Reusable across users and groups within a tenant

**Assignment Model**:
- Permissions are assigned via `permission_assignment` table
- Can be assigned directly to users OR to groups (users inherit from group membership)
- Assignment happens through permission sets or individual permissions

## Database Object Tracking

**IMPORTANT**: Before looking for any database object (function, table, view, etc.), always check `db-objects.md` first to find the latest definition location.

- `db-objects.md` - Complete tracking table of all 284+ database objects with:
  - Schema, object name, and type
  - Latest update file and line number
  - Complete update history across all migration files
  - Separation of migration vs ad-hoc updates
- `extract-db-objects.py` - Python script to regenerate the tracking table
- `db-objects.json` - JSON version for programmatic access

**Usage**: When asked about any function like `auth.has_permission`, first check `db-objects.md` to see it's defined in `004_create_permissions.sql:1588` with 1 total update.

**Key Columns**:
- **Last File**: The most recent file where the object was defined/modified
- **Line**: The exact line number in that file where the current definition starts
- **Migration Updates**: Chronological history of all changes (newest first)
- **Ad-hoc Updates**: Any updates from ad-hoc scripts (if DBADHOCDIRECTORY is set)

## Development Commands

### Database Setup and Migration
Use the PowerShell script `debee.ps1` for all database operations:

```powershell
# Full database setup (recreate, restore, update)
./debee.ps1 -Operations fullService

# Individual operations
./debee.ps1 -Operations recreateDatabase
./debee.ps1 -Operations restoreDatabase
./debee.ps1 -Operations updateDatabase
./debee.ps1 -Operations preUpdateScripts
./debee.ps1 -Operations postUpdateScripts

# Run specific migration range
./debee.ps1 -Operations updateDatabase -UpdateStartNumber 001 -UpdateEndNumber 010

# Use different environment
./debee.ps1 -Environment prod -Operations updateDatabase
```

### Running SQL Commands
Use the `execSql` operation built into debee for quick SQL execution:

```powershell
# Run SQL file
./debee.ps1 -Operations execSql -SqlFile examples/01-user-provisioning.sql

# Run inline SQL
./debee.ps1 -Operations execSql -Sql "SELECT * FROM auth.user_info LIMIT 5;"

# Interactive psql session
./debee.ps1 -Operations execSql
```

```bash
# Bash equivalent
./debee.sh -o execSql --sql-file examples/01-user-provisioning.sql
./debee.sh -o execSql --sql "SELECT * FROM auth.user_info LIMIT 5;"
./debee.sh -o execSql
```

```bash
# Python equivalent
python debee.py -o execSql --sql-file examples/01-user-provisioning.sql
python debee.py -o execSql --sql "SELECT * FROM auth.user_info LIMIT 5;"
python debee.py -o execSql
```

Priority: File > Inline command > Interactive session.

### Legacy Scripts
- `exec-sql.sh` - Standalone SQL execution (predates debee's `execSql` operation)
- `run.bat` - Simple Windows batch setup

### Environment Configuration
- Primary config: `debee.env`
- Local overrides: `.debee.env` (gitignored)
- Environment-specific: `debee.{environment}.env`

Key environment variables:
- `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD` - PostgreSQL connection
- `DBDESTDB` - Target database name (default: postgresql_permissionmodel)
- `DBUPDATESTARTNUMBER`, `DBUPDATEENDNUMBER` - Migration script ranges
- `DBBACKUPFILE`, `DBBACKUPTYPE` - Restore configuration

## SQL Migration Files

### Naming Convention
Files follow pattern: `XXX_description.sql` where XXX is a 3-digit number
- `000_create_database.sql` - Initial database creation
- `001_create_basic_structure.sql` - Core schemas and extensions
- `002_create_version_management.sql` - Database versioning system (`__version` table)
- `003_create_helpers.sql` - Helper functions
- `004_create_permissions.sql` - Main permissions system (largest file ~217KB)
- `010-047` - The v2 baseline (`postgresql_permissionmodel` version `2`, started in `010`, stopped in `047`)
- `048_update_permissions_v2-1.sql`, `049_update_permissions_v2-2.sql`, ... - Incremental v2 updates
- `99_fix_permissions.sql` - Post-update permission fixes

**Changes to shipped code go into a new update script — do NOT edit the baseline files (`010`-`047`) or an already-released update script.** Each update script:
- is the next free number below `099`, named `NNN_update_permissions_v2-N.sql`
- starts with `public.start_version_update('2.N', '<title>', _component := 'postgresql_permissionmodel', _description := ...)` and ends with `public.stop_version_update('2.N', _component := 'postgresql_permissionmodel')`
- contains full `create or replace` definitions of every changed function, plus any new error codes (`const.event_code` + `const.event_message` with `on conflict do nothing`, and the `error.raise_*` function)
- gets a CHANGELOG entry and a Version History row, an `error-codes.md` update for new codes, and a regenerated `db-objects.md`/`db-objects.json`

### Version Management
Simple version tracking using the `public.__version` table with component support:

```sql
-- Start version update (creates record with start timestamp)
select * from public.start_version_update('1.16', 'Description of update', 'Optional longer description', 'component_name');

-- Migration content here

-- Mark version complete (sets finish timestamp)
select * from public.stop_version_update('1.16', 'component_name');

-- Check if version already applied
select public.check_version('1.16', 'component_name');
```

**Version table structure**:
- Tracks `component`, `version`, `title`, `description`
- Records `execution_started` and `execution_finished` timestamps
- Supports multiple components (defaults to 'main')

## Key Functions and Usage Patterns

### User Management Functions
The user system uses three main tables for flexible multi-provider support and extensibility:

**Core User Management (`user_info` table)**:
- `auth.register_user()` - User registration and initial setup
- `auth.enable_user()` / `auth.disable_user()` - User status management
- `auth.lock_user()` / `auth.unlock_user()` - Account security controls
- `auth.update_user_password()` - Password management
- `auth.assign_user_default_groups()` - Automatic group assignment

**Identity Provider Management (`user_identity` table)**:
- `auth.ensure_user_from_provider()` - User provisioning from external providers
- `auth.create_user_identity()` - Add new identity provider to existing user
- `auth.enable_user_identity()` / `auth.disable_user_identity()` - Control provider access
- Multiple identities per user: Windows GUID, AzureAD UID, Google ID, etc.
- **Last used provider determines permissions** - `provider_groups` and `provider_roles` from most recent login drive permission calculations

**User Data (`user_data` table)**:
- `auth.update_user_data()` - Partial-merge update for profile + jsonb columns
- Three jsonb columns with shallow-merge semantics:
  - `settings` — app-level user config (locale, timezone, notifications)
  - `preferences` — UI/UX preferences (theme, sidebar, default view)
  - `custom_data` — app-specific extensible fields (employee_number, department)
- Pass only the keys to change; pass `null` value to remove a key
- Self-update is free (no RBAC), updating others requires `users.update_user_data`
- Auto-creates the `user_data` row on first update

### Authorization Functions
Core permission checking for any PostgreSQL application:
- `auth.has_permission(_tenant_id, _user_id, _perm_code, _throw_err := true)` - Single permission check
- `auth.has_permissions(_tenant_id, _user_id, _perm_codes[], _throw_err := true)` - Multiple permissions check
- `_throw_err` parameter allows silent permission checking without throwing unauthorized exceptions
- `auth.create_auth_event()` - Comprehensive audit logging
- Functions check both direct user permissions and inherited group permissions

### Permission Management

**Global Permission Structure**:
- `auth.create_permission_by_path()` / `auth.create_permission_by_code()` - Create hierarchical permissions
- Permissions use ltree paths like `users.create_user` or `users.read_users.read_gdpr_protected_data`
- Same permission structure across all tenants

**Tenant-Specific Permission Sets**:
- `auth.create_perm_set()` - Create tenant-specific permission sets (e.g., "Admin", "Manager", "Viewer")
- `auth.create_perm_set_permissions()` - Add global permissions to tenant permission sets
- `auth.copy_perm_set()` / `auth.duplicate_perm_set()` - Permission set duplication within/across tenants

**Assignment to Users/Groups**:
- `auth.assign_permission()` / `auth.unassign_permission()` - Assign permission sets or individual permissions
- Can assign directly to users or to groups (users inherit from group membership)
- All assignments stored in `permission_assignment` table

### Group Management
The system supports three group types for different authentication scenarios:

**Internal Groups** - Traditional membership stored in database:
- `auth.create_user_group()` / `auth.update_user_group()` - Group lifecycle
- `auth.create_user_group_member()` / `auth.delete_user_group_member()` - Direct membership management

**External Groups** - Membership determined by external identity provider mappings:
- `auth.create_external_user_group()` - Create groups that rely solely on external mappings
- `auth.create_user_group_mapping()` / `auth.delete_user_group_mapping()` - Map external groups to internal permission groups
- `auth.set_user_group_as_external()` - Configure group to use only external mappings
- Works with any identity provider: Windows Authentication, AzureAD, Google, Facebook, KeyCloak, LDAP, etc.
- Maps both `provider_groups` AND `provider_roles` - flexible for different provider implementations

**Hybrid Groups** - Combination of both membership models:
- `auth.set_user_group_as_hybrid()` - Allow both direct members and external mappings
- Supports both manual membership and external group synchronization

**Example Flow**:
1. User logs in via AzureAD → System updates `user_identity` with `provider_groups` and `provider_roles`
2. System marks this identity as "last used" for the user
3. Permission calculation uses the `provider_groups`/`provider_roles` from last used identity
4. System checks group mappings → Finds user's AzureAD group/role maps to "Super Admins"
5. User gets Super Admins permissions without being explicitly added as a member

**Multi-Identity Support**: Same user can have Windows Auth GUID, AzureAD UID, Google ID - permissions calculated from whichever they last used to login.

### Tenant Management
- `auth.create_tenant()` / `auth.update_tenant()` - Multi-tenant setup
- `auth.assign_tenant_owner()` - Tenant ownership assignment
- `auth.get_tenant_users()` / `auth.get_tenant_groups()` - Tenant queries

### API Key Management
API keys provide service-to-service authentication with a unique approach:
- `auth.create_api_key()` - Creates API key AND a "technical user" in `user_info`
- `auth.update_api_key()` / `auth.delete_api_key()` - API key lifecycle
- `auth.update_api_key_secret()` - Rotate API key secrets
- **Technical User Pattern**: Each API key gets its own user entry to maintain database consistency
- API keys can be assigned permission sets or individual permissions like regular users
- This design allows all permission checks to work uniformly for both human users and API services

### Common Integration Pattern
Most stored procedures should start with permission checks:
```sql
-- Example procedure pattern with exception throwing
if not auth.has_permission(_tenant_id, _user_id, 'orders.cancel_order') then
    perform internal.throw_no_permission(_user_id, 'orders.cancel_order');
end if;

-- OR use built-in exception throwing (default behavior)
perform auth.has_permission(_tenant_id, _user_id, 'orders.cancel_order');

-- OR silent check without exceptions
if auth.has_permission(_tenant_id, _user_id, 'orders.cancel_order', _throw_err := false) then
    -- user has permission, proceed
else
    -- user lacks permission, handle gracefully
end if;
```

**Important SQL Convention**: Always use fully qualified schema names (e.g., `auth.has_permission`, `public.__version`) to avoid "cannot find table/function" errors due to search_path issues.

## Error Codes
The system uses structured error codes (50001-52999) for different categories:
- 50001-50999: Informational events (tenant created, user updated, etc.)
- 52001-52999: Security errors (user not found, permission denied, etc.)

Refer to `readme.md:16-124` for complete error code documentation.

## Testing and Validation

### Running Tests
Tests use debee's built-in `runTests` operation:

```powershell
# Run all tests
./debee.ps1 -Operations runTests

# Run filtered tests (substring match on file/directory name)
./debee.ps1 -Operations runTests -TestFilter provider
./debee.ps1 -Operations runTests -TestFilter cache
```

```bash
# Bash equivalent
./debee.sh -o runTests
./debee.sh -o runTests --test-filter provider
```

```bash
# Python equivalent
python debee.py -o runTests
python debee.py -o runTests --test-filter provider
```

Run a single test file directly:
```bash
./debee.sh -o execSql --sql-file tests/test_provider_crud/001_create_provider.sql
```

### Test Organization

Tests support two forms:

**Flat test files** — single SQL files named `test_*.sql`:
```
tests/
├── test_connection.sql
├── test_provider_crud.sql
└── test_permission_cache_invalidation.sql
```

**Suite directories** — directories named `test_*/` with numbered SQL files:
```
tests/
└── test_connectivity/
    ├── test.json              # Optional manifest
    ├── 000_setup.sql          # Main phase (000-899)
    ├── 001_verify_connection.sql
    └── 999_cleanup.sql        # Cleanup phase (900-999)
```

Suite file phases:
- **000–899 (main)** — Setup + execution + verification, runs in order, stops on first error
- **900–999 (cleanup)** — Always runs if `always_cleanup: true` (default), failures are warnings only

### Suite Manifest (test.json)

Optional file inside a suite directory:
```json
{
  "name": "Connection Test Suite",
  "description": "Verify database connectivity and basic operations",
  "always_cleanup": true,
  "isolation": "none",
  "setup": ["shared/create_schema.sql"]
}
```

- **`always_cleanup`** — Run cleanup files (900-999) even if main phase fails (default: `true`)
- **`isolation`** — Isolation mode (see below, default: `"none"`)
- **`setup`** — Shared setup scripts from `tests/` directory, run before the suite's own files

### Isolation Modes

| Mode | Behavior |
|------|----------|
| `"none"` (default) | Files run individually against target database, changes persist |
| `"transaction"` | All setup + main files wrapped in `BEGIN/ROLLBACK`, changes rolled back automatically |
| `"database"` | Fresh database recreated before suite (calls `recreateDatabase` + `restoreDatabase`) |

### Test Execution Order

Global ordering controlled by `tests/tests.json`:
```json
{
  "order": [
    "test_connection.sql",
    "test_connectivity",
    "test_provider_crud.sql"
  ]
}
```

Items in `"order"` run first in specified order, unlisted items follow alphabetically. Ordering is applied before `--test-filter`.

### Shared Setup Scripts

Reusable SQL scripts in `tests/shared/`, referenced by suite manifests via the `"setup"` field. Paths are relative to `tests/`.

### Pass/Fail Detection

Debee scans test output for `PASS` and `FAIL` strings and checks psql exit codes. Output is colorized (green/red) with a summary at the end.

### Available Tests

All tests are organized as suite directories with `test.json` manifests:

| Suite | Description |
|-------|-------------|
| `test_connection/` | Basic database connectivity check |
| `test_connectivity/` | Connectivity with temp table operations |
| `test_provider_crud/` | Provider CRUD, journaling, capability flags, group mapping validation |
| `test_registration_login_events/` | User registration, login events, request_context flow |
| `test_disabled_locked_users/` | Disabled/locked user blocking, cache clearing, error codes |
| `test_permission_cache_invalidation/` | Cache invalidation (soft/hard), parameter validation, owner functions |
| `test_short_code/` | Hierarchical permission short codes, custom short codes |
| `test_correlation_id/` | Correlation ID flow to journal and user_event, search filtering |
| `test_event_code_management/` | Event category/code/message CRUD, system protection, cascading deletes |
| `test_language_translation/` | Language CRUD, translations, copy/overwrite, search, triggers |
| `test_group_members_and_delete_tenant/` | Group member queries, tenant deletion regression tests |
| `test_auth_group_member_tenant/` | Auth-layer group member and tenant functions with permission checks |
| `test_search_functions/` | All search functions: pagination, filtering, empty results |
| `test_tenant_scoping_security/` | v2.1 regressions: group owner ≠ tenant owner, cross-tenant assign/unassign/mapping rejected, API key expiry, `*_as_system` helpers |

**Test-writing rule:** don't call security-relevant functions as user 1. `auth.has_permissions` and resource access return `true` for user 1 straight away, so tenant, permission and owner logic never runs. Use a dedicated admin user with an explicit perm set, include a second tenant for any function that takes an id, and assert the returned column values, not just row counts.

### Writing New Tests

**Flat test files** should:
1. Be named `test_*.sql` in the `tests/` directory
2. Use `DO $$ ... $$` blocks for each test case
3. Use `RAISE NOTICE` for pass/fail output (text must contain `PASS:` or `FAIL:`)
4. Use `RAISE EXCEPTION` for hard failures
5. Clean up test data at the end

**Suite directories** should:
1. Be named `test_*/` in the `tests/` directory
2. Use numbered SQL files (`000_setup.sql`, `001_test.sql`, `900_cleanup.sql`)
3. Optionally include a `test.json` manifest for name, isolation mode, and shared setup
4. Place cleanup in the 900-999 range so it runs even on failure

### Manual Testing
- Use the topic-grouped scripts under `examples/` (see `examples/README.md`) for interactive, self-contained usage scenarios — each runs in a transaction that rolls back
- Always test permission inheritance and tenant isolation
- Verify audit events are properly logged

## Important Notes
- This is a pure PostgreSQL solution - no external dependencies beyond PostgreSQL extensions
- All timestamps use `timestamptz` for timezone awareness
- **Schema Security Model**: `public` and `auth` always check permissions; `internal` is for trusted contexts; `unsecure` is only for security internals
- **SQL Convention**: Always use fully qualified schema names (e.g., `auth.has_permission`, `public.__version`) to prevent search_path related errors
- **Variable Naming Convention**:
  - **Single `_` prefix is reserved for input parameters only** (e.g., `_user_id`). Never use a single underscore for local variables — readers expect single-underscore identifiers to be call-site arguments.
  - **Local variables use `__` prefix** (e.g., `__last_id`, `__resource_path_lt`).
  - **Return columns also use `__` prefix** (e.g., `__user_id` in `returns table(...)`).
  - **Locals that would clash with a `__` return column use `___` (triple underscore)** to disambiguate (e.g., `___user_id`). This prevents ambiguous column/variable errors in PL/pgSQL blocks that query functions returning `__`-prefixed columns.
  - Legacy code in this repo still uses single `_` for some locals — leave that alone in unrelated edits, but follow the new convention in any code you add or substantially rewrite.
- **Public API Types**: Functions in `public.*` and `auth.*` (the callable API surface) MUST use only stock PostgreSQL types and `jsonb` in parameters and return columns — never extension types like `ext.ltree`, `ext.ltree[]`, `ext.uuid`, etc. Convert at the boundary: accept `text`/`text[]` and convert internally with `ext.text2ltree(...)`; return paths as `text` (cast via `::text`). Rationale: downstream code generators (Elixir, Go, TypeScript) and many client libraries cannot map extension types and fail with "dbType '_ltree' not found" or similar. Tables, `internal.*`, `unsecure.*`, and `helpers.*` may use extension types freely.
- **No `returns setof <table>` on the public API surface**: Functions in `public.*`, `auth.*`, and `internal.*` MUST declare an explicit `returns table(...)` column list — never `returns setof <table>`. `setof <table>` implicitly exposes every physical column (in storage order), which leaks internal implementation columns (`nrm_search_data`, `ts_search_data`, `ext.ltree` paths) and silently changes whenever a column is added to the table. An explicit `returns table(...)` freezes the contract: pick the columns, cast `ext.ltree` → `text` at the boundary, drop internal search columns, and name return columns with the `__` prefix (see Variable Naming Convention). When a body's `insert/update ... returning *` or `select * from <tbl>` feeds the result, replace the `*` with the explicit source-column list. **Gotcha**: if function A (`public/auth/internal`) reads columns from converted function B, it must reference B's new `__`-prefixed output names — and in a plpgsql function those names collide with the `returns table` OUT-parameter variables, so alias the source and qualify (`select b.__journal_id from create_journal_message(...) b`). `unsecure.*` and `helpers.*` may still return `setof <table>`.
- **Group Mapping Strategy**: Supports internal, external, and hybrid group membership models for flexible integration with any identity provider (Windows Auth, AzureAD, Google, Facebook, KeyCloak, LDAP, etc.)
- **User Data**: `user_data` table has three jsonb columns (`settings`, `preferences`, `custom_data`) with partial merge via `auth.update_user_data`. Additional custom columns can still be added, or create separate tables referencing `user_info.user_id`
- Permission caching is implemented - use `unsecure.clear_permission_cache()` when needed
- **API Keys as Technical Users**: Each API key creates a technical user in `user_info`, allowing uniform permission handling across human and service accounts
- System includes comprehensive audit logging for all security events
- The `../keen-auth-permissions` library provides application-level wrappers around these SQL functions
- Can be integrated into any PostgreSQL project by running the migration scripts
- External group mappings eliminate need to sync user membership - permissions are resolved dynamically from last used identity's `provider_groups`/`provider_roles`
- Users can have multiple identities (Windows, AzureAD, Google, etc.) but permissions calculated from most recent login provider