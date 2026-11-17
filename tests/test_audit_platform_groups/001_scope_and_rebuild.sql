set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Creating platform groups (tenant 1, platform.manage_platform_objects)
--   Global Support : all tenants, PG Admin       - gina
--   EU Support     : ABC, CDE,    PG Admin       - anna
--   FGH Key Account: FGH,         PG Support     - rule mapping "in Azure KA-FGH"
-- ============================================================================
do $$
begin
    raise notice 'TEST 1: who may create platform groups';
end $$;

select pg_temp.pg_expect('system_admin creates a platform group'
    , 'select * from auth.create_platform_group(''pg'', {sys}, ''pg'', ''X'', true)', '32001');
select pg_temp.pg_expect('a tenant admin creates a platform group'
    , 'select * from auth.create_platform_group(''pg'', {abc_admin}, ''pg'', ''X'', true)', '32001');
select pg_temp.pg_expect('a scope with an unknown tenant'
    , 'select * from auth.create_platform_group(''pg'', {full}, ''pg'', ''X'', false, array[-5])', '34003');

do $$
declare
    __full bigint := pg_temp.pg('full')::bigint;
    __g    int;
begin
    select g.__user_group_id from auth.create_platform_group('pg', __full, 'pg', 'Global Support', true) g into __g;
    insert into _pg values ('g_global', __g);
    perform auth.assign_permission('pg', __full, 'pg', __g, null, 'pg_admin', null, 1);
    perform auth.create_user_group_member('pg', __full, 'pg', __g, pg_temp.pg('gina')::bigint, 1);

    select g.__user_group_id from auth.create_platform_group('pg', __full, 'pg', 'EU Support', false
        , array[pg_temp.pg('abc')::int, pg_temp.pg('cde')::int]) g into __g;
    insert into _pg values ('g_eu', __g);
    perform auth.assign_permission('pg', __full, 'pg', __g, null, 'pg_admin', null, 1);
    perform auth.create_user_group_member('pg', __full, 'pg', __g, pg_temp.pg('anna')::bigint, 1);

    select g.__user_group_id from auth.create_platform_group('pg', __full, 'pg', 'FGH Key Account', false
        , array[pg_temp.pg('fgh')::int]) g into __g;
    insert into _pg values ('g_ka', __g);
    perform auth.assign_permission('pg', __full, 'pg', __g, null, 'pg_support', null, 1);
    perform auth.create_user_group_rule_mapping('pg', __full, 'pg', __g
        , _rule := '{"mode": "conditional", "conditions": [{"field": "provider_groups", "op": "includes", "values": [{"value": "ka-fgh-oid", "label": "KA-FGH"}]}]}'
        , _tenant_id := 1);

    perform pg_temp.pg_is('the groups live in tenant 1, flagged as platform'
        , (select string_agg(ug.code || ':' || ug.tenant_id || ':' || ug.is_platform || ':' || ug.is_for_all_tenants, ',' order by ug.code)
           from auth.user_group ug where ug.user_group_id in (pg_temp.pg('g_global')::int, pg_temp.pg('g_eu')::int, pg_temp.pg('g_ka')::int))
        , 'eu_support:1:true:false,fgh_key_account:1:true:false,global_support:1:true:true');

    perform pg_temp.pg_is('get_platform_groups shows the scopes'
        , (select string_agg(p.__code || ':' || p.__is_for_all_tenants || ':' || coalesce(array_length(p.__scope_tenant_ids, 1), 0) || ':' || p.__member_count, ',' order by p.__code)
           from auth.get_platform_groups(__full, 'pg') p
           where p.__user_group_id in (pg_temp.pg('g_global')::int, pg_temp.pg('g_eu')::int, pg_temp.pg('g_ka')::int))
        , 'eu_support:false:2:1,fgh_key_account:false:1:0,global_support:true:0:1');
end $$;

select pg_temp.pg_expect('a platform group outside tenant 1'
    , 'update auth.user_group set is_platform = true where user_group_id = (select user_group_id from auth.user_group where tenant_id = {abc} limit 1)', '23514');

-- ============================================================================
-- The permission rebuild: platform members hold the group's perm set in the
-- tenants in scope, and nothing in tenant 1
-- ============================================================================
do $$
declare
    __anna bigint := pg_temp.pg('anna')::bigint;
    __gina bigint := pg_temp.pg('gina')::bigint;
    __kate bigint;
    __r    record;
begin
    raise notice 'TEST 2: the rebuild grants in the tenants in scope';

    perform pg_temp.pg_is('anna: ABC and CDE', pg_temp.pg_holds(__anna, 'tenants.update_tenant'), 'pg_abc,pg_cde');
    perform pg_temp.pg_is('gina: every tenant but tenant 1', pg_temp.pg_holds(__gina, 'tenants.update_tenant'), 'pg_abc,pg_cde,pg_fgh');

    -- kate signs in with the Azure group KA-FGH
    select * from auth.ensure_user_from_provider('pg', 3, 'pg', 'pg_aad', 'uid-kate', 'oid-kate'
        , 'pg_kate', 'Kate', 'kate@platform.com', null) into __r;
    __kate := __r.__user_id;
    insert into _pg values ('kate', __kate);
    perform auth.ensure_groups_and_permissions('pg', 3, 'pg', __kate, 'pg_aad', array['ka-fgh-oid'], null);

    perform pg_temp.pg_is('kate (rule mapping): PG Support in FGH', pg_temp.pg_holds(__kate, 'users.read_users'), 'pg_fgh');
    perform pg_temp.pg_is('kate: nothing more', pg_temp.pg_holds(__kate, 'tenants.update_tenant'), '');
end $$;

-- ============================================================================
-- The tenants see nothing
-- ============================================================================
do $$
declare
    __anna bigint := pg_temp.pg('anna')::bigint;
    __abc  int := pg_temp.pg('abc')::int;
begin
    raise notice 'TEST 3: the tenants contain nothing';

    perform pg_temp.pg_is('anna is not a member of any tenant'
        , (select count(*)::text from auth.tenant_memberships where user_id = __anna), '0');
    perform pg_temp.pg_is('ABC''s user list doesn''t show anna'
        , (select count(*)::text from auth.get_tenant_users('pg', pg_temp.pg('abc_admin')::bigint, 'pg', __abc) u where u.__user_id = __anna), '0');
    perform pg_temp.pg_is('anna''s groups in ABC are empty'
        , (select coalesce(array_to_string(p.__groups, ','), '') from unsecure.recalculate_user_permissions('pg', __anna, __abc) p), '');
    perform pg_temp.pg_is('ABC''s group search doesn''t show platform groups'
        , (select count(*)::text from auth.search_user_groups(pg_temp.pg('abc_admin')::bigint, 'pg', null, 1, 100, __abc) g
           where g.__code in ('eu_support', 'global_support', 'fgh_key_account')), '0');
end $$;

select pg_temp.pg_expect('ABC admin reads the platform group by id'
    , 'select * from auth.get_user_group_by_id(''pg'', {abc_admin}, ''pg'', {g_eu}, {abc})', '33011');

-- ============================================================================
-- Tenant 1: only with the platform permissions
-- ============================================================================
do $$
begin
    raise notice 'TEST 4: tenant-1 admins without the platform permissions see nothing';
    perform pg_temp.pg_is('system_admin''s group search hides platform groups'
        , (select count(*)::text from auth.search_user_groups(pg_temp.pg('sys')::bigint, 'pg', null, 1, 100, 1) g
           where g.__code in ('eu_support', 'global_support', 'fgh_key_account')), '0');
    perform pg_temp.pg_is('system_admin''s tenant groups hide platform groups'
        , (select count(*)::text from auth.get_tenant_groups('pg', pg_temp.pg('sys')::bigint, 'pg', 1) g
           where g.__group_code in ('eu_support', 'global_support', 'fgh_key_account')), '0');
    perform pg_temp.pg_is('full_admin''s group search shows them'
        , (select count(*)::text from auth.search_user_groups(pg_temp.pg('full')::bigint, 'pg', null, 1, 100, 1) g
           where g.__code in ('eu_support', 'global_support', 'fgh_key_account')), '3');
end $$;

select pg_temp.pg_expect('system_admin reads a platform group'
    , 'select * from auth.get_user_group_by_id(''pg'', {sys}, ''pg'', {g_eu}, 1)', '32001');
select pg_temp.pg_expect('system_admin reads its members'
    , 'select * from auth.get_user_group_members(''pg'', {sys}, ''pg'', {g_eu}, 1)', '32001');
select pg_temp.pg_expect('system_admin reads its mappings'
    , 'select * from auth.get_user_group_mappings(''pg'', {sys}, ''pg'', {g_ka}, 1)', '32001');
select pg_temp.pg_expect('system_admin adds a member'
    , 'select * from auth.create_user_group_member(''pg'', {sys}, ''pg'', {g_eu}, {sys}, 1)', '32001');
select pg_temp.pg_expect('system_admin assigns a perm set to it'
    , 'select * from auth.assign_permission(''pg'', {sys}, ''pg'', {g_eu}, null, ''pg_support'', null, 1)', '32001');
select pg_temp.pg_expect('system_admin maps an Azure group to it'
    , 'select * from auth.create_user_group_mapping(''pg'', {sys}, ''pg'', {g_eu}, ''pg_aad'', ''everyone'', _tenant_id := 1)', '32001');
select pg_temp.pg_expect('system_admin renames it'
    , 'select * from auth.update_user_group(''pg'', {sys}, ''pg'', {g_eu}, ''Mine'', true, true, false, 1)', '32001');
select pg_temp.pg_expect('system_admin disables it'
    , 'select * from auth.disable_user_group(''pg'', {sys}, ''pg'', {g_eu}, 1)', '32001');
select pg_temp.pg_expect('system_admin deletes it'
    , 'select auth.delete_user_group(''pg'', {sys}, ''pg'', {g_eu}, 1)', '32001');
select pg_temp.pg_expect('system_admin changes its scope'
    , 'select auth.update_platform_group_scope(''pg'', {sys}, ''pg'', {g_eu}, true, null)', '32001');
select pg_temp.pg_expect('system_admin lists platform groups'
    , 'select * from auth.get_platform_groups({sys}, ''pg'')', '32001');
select pg_temp.pg_expect('scope of an ordinary group'
    , 'select auth.update_platform_group_scope(''pg'', {full}, ''pg'', (select user_group_id from auth.user_group where tenant_id = 1 and code = ''tenant_members''), true, null)', '33027');
