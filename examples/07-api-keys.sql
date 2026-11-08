/*
 * Example 07 — API keys as technical users
 * ========================================
 *
 * Showcases service authentication:
 *   - each API key gets its own "technical user", so permission checks work the
 *     same for humans and services
 *   - authenticate with the key and see its effective permissions
 *   - grant the key an extra permission
 *   - create a plain service user (no key)
 *
 * Standalone plain SQL — run one statement at a time in any client. Data persists;
 * run examples/cleanup.sql to reset. Acts as the system user (user_id = 1).
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;


-- ── Setup: a permission hierarchy + a set to grant to the key ────────────────
select * from auth.create_permission('examples', 1, 'ex07', 'Reports');
select * from auth.create_permission('examples', 1, 'ex07', 'Export reports', _parent_full_code := 'reports');
select * from auth.create_permission('examples', 1, 'ex07', 'Read reports',   _parent_full_code := 'reports');
select * from auth.create_perm_set('examples', 1, 'ex07', 'Reporting',
        _permissions := array['reports.export_reports']);


-- ── Aspect: create an API key (a technical user is created automatically) ────
-- Passing explicit _api_key / _api_secret so we can authenticate below; omit them
-- to have the system generate a random pair (returned by the function).
select * from auth.create_api_key('examples', 1, 'ex07',
        _title := 'Blue Rose Export',
        _description := 'Nightly export job',
        _perm_set_code := (select code from auth.perm_set where code = helpers.get_code('Reporting') and tenant_id = 1),
        _permission_full_codes := null,
        _api_key := 'blue-rose-key',
        _api_secret := 'blue-rose-secret');


-- ── Aspect: authenticate with the key → technical user ───────────────────────
-- Returns the technical user and the outcome (14010 apikey_validated; failures
-- such as 30001 wrong secret or 30006 expired return null user columns and are
-- logged). Permissions are then checked like for any user:
select v.*, auth.has_permission(v.__user_id, 'ex07', 'reports.export_reports', 1, false) as can_export
from auth.create_api_key_validation_attempt('examples', 1, 'ex07',
        _api_key := 'blue-rose-key', _api_secret := 'blue-rose-secret') v;


-- ── Aspect: grant an additional permission directly to the key ───────────────
select * from auth.assign_api_key_permissions('examples', 1, 'ex07',
        _api_key_id := (select api_key_id from auth.api_key where title = 'Blue Rose Export' and tenant_id = 1),
        _perm_set_code := null,
        _permission_full_codes := array['reports.read_reports']);

-- re-validate — the technical user now also has reports.read_reports
select v.*, auth.has_permission(v.__user_id, 'ex07', 'reports.read_reports', 1, false) as can_read
from auth.create_api_key_validation_attempt('examples', 1, 'ex07',
        _api_key := 'blue-rose-key', _api_secret := 'blue-rose-secret') v;


-- ── Aspect: a plain service user (no API key) — e.g. a background worker ──────
select * from auth.create_service_user_info('examples', 1, 'ex07',
        _username := 'gordon.cole@twinpeaks.com',
        _email := 'gordon.cole@twinpeaks.com',
        _display_name := 'Gordon Cole');
