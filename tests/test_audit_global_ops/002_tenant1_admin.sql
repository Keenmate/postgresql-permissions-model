set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- sysadmin holds the same permissions in tenant 1: every call works, also
-- when the app passes _tenant_id = B.
-- ============================================================================
do $$
begin
    raise notice '';
    raise notice '--- 002: tenant 1 admin manages global objects from any tenant ---';

    perform pg_temp.d07_expect('tenant 1: create_permission',
        'select * from auth.create_permission(''t'', {sysadmin_id}, ''c'', ''D07 perm'', null, true, _tenant_id := {b_id})', null);
    perform pg_temp.d07_expect('tenant 1: create_provider',
        'select * from auth.create_provider(''t'', {sysadmin_id}, ''c'', ''d07_idp'', ''D07 IdP'', _tenant_id := {b_id})', null);
    perform pg_temp.d07_expect('tenant 1: ensure_provider (existing)',
        'select * from auth.ensure_provider(''t'', {sysadmin_id}, ''c'', ''d07_idp'', ''D07 IdP'', _tenant_id := {b_id})', null);
    perform pg_temp.d07_expect('tenant 1: create_resource_type',
        'select * from auth.create_resource_type(''t'', {sysadmin_id}, ''c'', ''d07_type'', ''D07 type'', _tenant_id := {b_id})', null);
    perform pg_temp.d07_expect('tenant 1: create_token_type',
        'select * from public.create_token_type(''t'', {sysadmin_id}, ''c'', ''d07_token'', 60, {b_id})', null);
    perform pg_temp.d07_expect('tenant 1: create_language',
        'select * from public.create_language(''t'', {sysadmin_id}, ''c'', ''d7'', ''D07 language'', _tenant_id := {b_id})', null);
    perform pg_temp.d07_expect('tenant 1: update_sys_param',
        'select * from auth.update_sys_param({sysadmin_id}, ''auth'', ''perm_cache_timeout_in_s'', null, 300)', null);
    perform pg_temp.d07_expect('tenant 1: create_event_category',
        'select * from public.create_event_category(''t'', {sysadmin_id}, ''c'', ''d07_cat'', ''D07'', 900000, 900099)', null);
end $$;
