set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Only tenant owners make or unmake tenant admins
-- ============================================================================
do $$
begin
    raise notice 'TEST 1: tenant admins can''t make tenant admins';
end $$;

select pg_temp.ah_expect('a plain tenant admin can''t assign perm sets at all'
    , 'select * from auth.assign_permission(''ah'', {admin}, ''ah'', null, {user}, ''tenant_admin'', null, {abc})', '32001');
select pg_temp.ah_expect('the admin assigns tenant_admin to a user'
    , 'select * from auth.assign_permission(''ah'', {padmin}, ''ah'', null, {user}, ''tenant_admin'', null, {abc})', '32010');
select pg_temp.ah_expect('the admin adds a user to Tenant Admins'
    , 'select * from auth.create_user_group_member(''ah'', {admin}, ''ah'', {g_admins}, {user}, {abc})', '32010');
select pg_temp.ah_expect('the admin maps an Azure group to Tenant Admins'
    , 'select * from auth.create_user_group_rule_mapping(''ah'', {admin}, ''ah'', {g_admins}, _rule := ''{"mode": "always"}'', _tenant_id := {abc})', '32010');
select pg_temp.ah_expect('the admin assigns tenant_admin to another group'
    , 'select * from auth.assign_permission(''ah'', {padmin}, ''ah'', {g_members}, null, ''tenant_admin'', null, {abc})', '32010');
select pg_temp.ah_expect('the admin adds a permission to the tenant_admin set'
    , 'select * from auth.create_perm_set_permissions(''ah'', {padmin}, ''ah'', {ps_admin}, array[''tenants.get_users''], {abc})', '32010');
select pg_temp.ah_expect('the admin renames the tenant_admin set'
    , 'select * from auth.update_perm_set(''ah'', {padmin}, ''ah'', {ps_admin}, ''Admins'', true, {abc})', '32010');
select pg_temp.ah_expect('the admin makes someone an owner'
    , 'select * from auth.create_owner(''ah'', {admin}, ''ah'', {user}, null, {abc})', '32001');

do $$
declare
    __owner bigint := pg_temp.ah('owner')::bigint;
    __abc   int := pg_temp.ah('abc')::int;
    __user  bigint := pg_temp.ah('user')::bigint;
begin
    raise notice 'TEST 2: owners do';

    perform auth.assign_permission('ah', __owner, 'ah', null, __user, 'tenant_admin', null, __abc);
    perform pg_temp.ah_is('the owner made the user an admin'
        , auth.has_permission(__user, 'ah', 'tenants.update_tenant', __abc, _throw_err := false)::text, 'true');
    perform auth.create_user_group_member('ah', __owner, 'ah', pg_temp.ah('g_admins')::int, pg_temp.ah('user2')::bigint, __abc);
    perform pg_temp.ah_is('the owner added user2 to Tenant Admins'
        , auth.has_permission(pg_temp.ah('user2')::bigint, 'ah', 'tenants.update_tenant', __abc, _throw_err := false)::text, 'true');
end $$;

select pg_temp.ah_expect('the admin removes another admin''s tenant_admin'
    , 'select * from auth.unassign_permission(''ah'', {padmin}, ''ah'', (select assignment_id from auth.permission_assignment where user_id = {user} and tenant_id = {abc}), {abc})', '32010');
select pg_temp.ah_expect('the admin removes user2 from Tenant Admins'
    , 'select auth.delete_user_group_member(''ah'', {admin}, ''ah'', {g_admins}, {user2}, {abc})', '32010');

-- ============================================================================
-- Tenant admins manage the tenant's groups (and its rules, not global ones)
-- ============================================================================
do $$
declare
    __admin bigint := pg_temp.ah('admin')::bigint;
    __abc   int := pg_temp.ah('abc')::int;
    __g     int;
begin
    raise notice 'TEST 3: tenant admins manage groups';

    select g.__user_group_id from auth.create_user_group('ah', __admin, 'ah', 'AH Team', _tenant_id := __abc) g into __g;
    perform auth.create_user_group_member('ah', __admin, 'ah', __g, pg_temp.ah('user')::bigint, __abc);
    perform auth.create_user_group_rule_mapping('ah', __admin, 'ah', __g
        , _rule := '{"mode": "conditional", "conditions": [{"field": "email_domain", "op": "is", "values": ["abc.com"]}]}', _tenant_id := __abc);
    perform auth.create_user_group_member('ah', __admin, 'ah', pg_temp.ah('g_members')::int, pg_temp.ah('user')::bigint, __abc);
    perform pg_temp.ah_is('the admin built a group with a member and a rule mapping'
        , (select count(*)::text from auth.user_group_member m where m.user_group_id = __g)
              || ':' || (select count(*)::text from auth.user_group_mapping m where m.user_group_id = __g), '1:1');
    perform auth.update_user_group('ah', __admin, 'ah', __g, 'AH Team 2', true, true, false, __abc);
    perform auth.delete_user_group('ah', __admin, 'ah', __g, __abc);
    perform pg_temp.ah_is('and deleted it', (select count(*)::text from auth.user_group where user_group_id = __g), '0');
end $$;

select pg_temp.ah_expect('the admin adds a member to a group whose rights they lack (D-19)'
    , 'select * from auth.create_user_group_member(''ah'', {admin}, ''ah'', {g_readers}, {user}, {abc})', '32010');
select pg_temp.ah_expect('the admin creates a global rule'
    , 'select * from auth.create_rule(''ah'', {admin}, ''ah'', ''X'', ''{"mode": "always"}'', _is_global := true, _tenant_id := {abc})', '32001');

do $$
declare
    __full bigint := pg_temp.ah('full')::bigint;
begin
    raise notice 'TEST 4: tenant 1 is not affected';
    perform auth.create_tenant_template_group('ah', __full, 'ah'
        , (select t.__tenant_template_id from auth.get_tenant_templates(__full, 'ah') t where t.__is_default)
        , 'AH Extra Admins', array['tenant_admin']);
    perform pg_temp.ah_is('full_admin puts tenant_admin into a template'
        , (select count(*)::text from auth.tenant_template_group where title = 'AH Extra Admins'), '1');
    perform pg_temp.ah_is('the tenant_admin copies are owner-only, tenant 1''s too'
        , (select string_agg(distinct ps.is_owner_only::text, ',') from auth.perm_set ps where ps.code = 'tenant_admin'), 'true');

    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit: tenant owners above tenant admins - Finished';
    raise notice '=================================================================';
end $$;
