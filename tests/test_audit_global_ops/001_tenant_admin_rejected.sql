set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- admin_b holds every permission, but only in tenant B: every global
-- operation is rejected with 32001. 'nobody' is rejected where there was no
-- permission check at all (system parameters, event codes).
-- ============================================================================
do $$
begin
    raise notice '';
    raise notice '--- 001: tenant B admin cannot change global objects ---';

    -- permission tree
    perform pg_temp.d07_expect('create_permission',
        'select * from auth.create_permission(''t'', {admin_b_id}, ''c'', ''D07 perm'', null, true, _tenant_id := {b_id})', '32001');
    perform pg_temp.d07_expect('set_permission_as_assignable',
        'select * from auth.set_permission_as_assignable(''t'', {admin_b_id}, ''c'', null, ''users.lock_user'', false, {b_id})', '32001');

    -- providers
    perform pg_temp.d07_expect('create_provider',
        'select * from auth.create_provider(''t'', {admin_b_id}, ''c'', ''d07_idp'', ''D07 IdP'', _tenant_id := {b_id})', '32001');
    perform pg_temp.d07_expect('ensure_provider',
        'select * from auth.ensure_provider(''t'', {admin_b_id}, ''c'', ''d07_idp'', ''D07 IdP'', _tenant_id := {b_id})', '32001');
    perform pg_temp.d07_expect('disable_provider',
        'select * from auth.disable_provider(''t'', {admin_b_id}, ''c'', ''email'', {b_id})', '32001');

    -- resource types
    perform pg_temp.d07_expect('create_resource_type',
        'select * from auth.create_resource_type(''t'', {admin_b_id}, ''c'', ''d07_type'', ''D07 type'', _tenant_id := {b_id})', '32001');

    -- token types
    perform pg_temp.d07_expect('create_token_type',
        'select * from public.create_token_type(''t'', {admin_b_id}, ''c'', ''d07_token'', 60, {b_id})', '32001');

    -- languages
    perform pg_temp.d07_expect('create_language',
        'select * from public.create_language(''t'', {admin_b_id}, ''c'', ''d7'', ''D07 language'', _tenant_id := {b_id})', '32001');
    perform pg_temp.d07_expect('delete_language',
        'select * from public.delete_language(''t'', {admin_b_id}, ''c'', ''d7x'', {b_id})', '32001');

    -- system parameters and event codes: no permission check existed
    perform pg_temp.d07_expect('update_sys_param (nobody)',
        'select * from auth.update_sys_param({nobody_id}, ''auth'', ''perm_cache_timeout_in_s'', null, 1)', '32001');
    perform pg_temp.d07_expect('update_sys_param (tenant B admin)',
        'select * from auth.update_sys_param({admin_b_id}, ''auth'', ''perm_cache_timeout_in_s'', null, 1)', '32001');
    perform pg_temp.d07_expect('create_event_category (nobody)',
        'select * from public.create_event_category(''t'', {nobody_id}, ''c'', ''d07_cat'', ''D07'', 900000, 900099)', '32001');
    perform pg_temp.d07_expect('create_event_code (nobody)',
        'select * from public.create_event_code(''t'', {nobody_id}, ''c'', 11999, ''d07_code'', ''tenant_event'', ''D07 code'')', '32001');

    -- translations are global (v2.16): managed from tenant 1 only
    perform pg_temp.d07_expect('create_translation',
        'select * from public.create_translation(''t'', {admin_b_id}, ''c'', ''en'', ''d07_group'', ''D07'', ''d07_obj'', _tenant_id := {b_id})', '32001');
    perform pg_temp.d07_expect('update_translation',
        'select * from public.update_translation(''t'', {admin_b_id}, ''c'', {tr_id}, ''Hijacked'', {b_id})', '32001');
    perform pg_temp.d07_expect('delete_translation',
        'select * from public.delete_translation(''t'', {admin_b_id}, ''c'', {tr_id}, {b_id})', '32001');
    perform pg_temp.d07_expect('copy_translations',
        'select * from public.copy_translations(''t'', {admin_b_id}, ''c'', ''en'', ''en'', true, null, {b_id}, 1, {b_id})', '32001');
end $$;

do $$
begin
    if exists(select from auth.provider where code = 'd07_idp')
        or exists(select from const.token_type where code = 'd07_token')
        or exists(select from const.language where code = 'd7')
        or not exists(select from const.language where code = 'en')
        or exists(select from const.resource_type where code = 'd07_type') then
        raise notice 'FAIL: a global object was created or deleted by the tenant B admin';
    else
        raise notice 'PASS: no global object created or deleted';
    end if;

    if (select number_value from const.sys_param where group_code = 'auth' and code = 'perm_cache_timeout_in_s') = 1 then
        raise notice 'FAIL: perm_cache_timeout_in_s was changed';
    else
        raise notice 'PASS: perm_cache_timeout_in_s unchanged';
    end if;

    if (select value from public.translation where translation_id = (select val::int from _d07 where key = 'tr_id')) = 'Hijacked' then
        raise notice 'FAIL: tenant 1 translation changed';
    else
        raise notice 'PASS: tenant 1 translation unchanged';
    end if;
end $$;
