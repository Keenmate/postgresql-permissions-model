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

-- Translations are global: a tenant 1 admin manages them whatever _tenant_id is
-- passed, rows always land in tenant 1, and every tenant reads the same rows.
do $$
declare
    __tr int;
begin
    perform pg_temp.d07_expect('tenant 1: create_translation',
        'select * from public.create_translation(''t'', {sysadmin_id}, ''c'', ''en'', ''d07_group'', ''D07'', ''d07_obj'', _tenant_id := {b_id})', null);

    select translation_id from public.translation where data_group = 'd07_group' and data_object_code = 'd07_obj' into __tr;
    if (select tenant_id from public.translation where translation_id = __tr) = 1 then
        raise notice 'PASS: translation created from tenant B lands in tenant 1 (global)';
    else
        raise notice 'FAIL: translation not stored as global';
    end if;

    perform pg_temp.d07_expect('tenant 1: update_translation',
        format('select * from public.update_translation(''t'', {sysadmin_id}, ''c'', %s, ''D07 updated'', {b_id})', __tr), null);

    if exists(select from public.search_translations((select val::bigint from _d07 where key = 'admin_b_id'), 'c',
                  _language_code := 'en', _data_group := 'd07_group',
                  _tenant_id := (select val::int from _d07 where key = 'b_id')) s) then
        raise notice 'PASS: tenant B admin reads the global rows from tenant B';
    else
        raise notice 'FAIL: search_translations from tenant B returns nothing';
    end if;
end $$;
