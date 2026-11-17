set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- API keys
-- ============================================================================
do $$
declare
    __k int;
begin
    raise notice 'TEST 7: API key permissions';
    select k.__api_key_id from auth.create_api_key('esc', 1, 'esc', 'ESC key', null, null, null, _tenant_id := pg_temp.esc('esc')::int) k
    into __k;
    insert into _esc values ('key', __k);
    perform auth.assign_api_key_permissions('esc', 1, 'esc', __k, 'elevated', null, pg_temp.esc('esc')::int);
end $$;

select pg_temp.esc_expect('helper creates a key with tenant_admin'
    , 'select * from auth.create_api_key(''esc'', {helper}, ''esc'', ''k1'', null, ''tenant_admin'', null, _tenant_id := {esc})', '32010');
select pg_temp.esc_expect('helper creates a key with a permission they lack'
    , 'select * from auth.create_api_key(''esc'', {helper}, ''esc'', ''k2'', null, null, array[''tenants.update_tenant''], _tenant_id := {esc})', '32010');
select pg_temp.esc_expect('helper gives a key a permission they lack'
    , 'select * from auth.assign_api_key_permissions(''esc'', {helper}, ''esc'', {key}, null, array[''tenants.update_tenant''], {esc})', '32010');
select pg_temp.esc_expect('helper takes a perm set they lack from a key'
    , 'select * from auth.unassign_api_key_permissions(''esc'', {helper}, ''esc'', {key}, ''elevated'', null, {esc})', '32010');
select pg_temp.esc_ok('helper creates a key with a set they hold'
    , 'select * from auth.create_api_key(''esc'', {helper}, ''esc'', ''k3'', null, ''small'', array[''users.read_users''], _tenant_id := {esc})');
select pg_temp.esc_ok('helper gives a key a permission they hold'
    , 'select * from auth.assign_api_key_permissions(''esc'', {helper}, ''esc'', {key}, null, array[''users.read_users''], {esc})');

-- ============================================================================
-- Invitations: checked against the inviter when created
-- ============================================================================
do $$
begin
    raise notice 'TEST 8: invitations';
end $$;

select pg_temp.esc_expect('helper invites with tenant_admin'
    , 'select * from auth.create_invitation(''esc'', {helper}, ''esc'', {esc}, ''new1@test.com'', ''[{"action_type_code": "assign_perm_set", "payload": {"perm_set_code": "tenant_admin"}}]'')', '32010');
select pg_temp.esc_expect('helper invites with a permission they lack'
    , 'select * from auth.create_invitation(''esc'', {helper}, ''esc'', {esc}, ''new2@test.com'', ''[{"action_type_code": "assign_permission", "payload": {"permission_code": "tenants.update_tenant"}}]'')', '32010');
select pg_temp.esc_expect('helper invites into ESC Admins'
    , 'select * from auth.create_invitation(''esc'', {helper}, ''esc'', {esc}, ''new3@test.com'', ''[{"action_type_code": "add_group_member", "payload": {"user_group_id": {g_admins}}}]'')', '32010');
select pg_temp.esc_ok('helper invites with what they hold'
    , 'select * from auth.create_invitation(''esc'', {helper}, ''esc'', {esc}, ''new4@test.com'', ''[{"action_type_code": "assign_perm_set", "payload": {"perm_set_code": "small"}}, {"action_type_code": "add_group_member", "payload": {"user_group_id": {g_small}}}]'')');

do $$
begin
    perform pg_temp.esc_is('only the allowed invitation exists'
        , (select string_agg(i.target_email, ',' order by i.target_email) from auth.invitation i
           where i.tenant_id = pg_temp.esc('esc')::int)
        , 'new4@test.com');
end $$;

-- ============================================================================
-- Owners: a tenant owner holds tenant_owner, a group owner adds members
-- ============================================================================
do $$
begin
    raise notice 'TEST 9: owners';
    insert into auth.owner (created_by, tenant_id, user_id) values ('esc', pg_temp.esc('esc')::int, pg_temp.esc('target2')::bigint);
end $$;

select pg_temp.esc_expect('helper makes someone tenant owner'
    , 'select * from auth.create_owner(''esc'', {helper}, ''esc'', {target}, null, {esc})', '32010');
select pg_temp.esc_expect('helper makes themselves tenant owner'
    , 'select * from auth.create_owner(''esc'', {helper}, ''esc'', {helper}, null, {esc})', '32010');
select pg_temp.esc_expect('helper removes a tenant owner'
    , 'select auth.delete_owner(''esc'', {helper}, ''esc'', {target2}, null, {esc})', '32010');
select pg_temp.esc_expect('helper makes someone owner of ESC Admins'
    , 'select * from auth.create_owner(''esc'', {helper}, ''esc'', {target}, {g_admins}, {esc})', '32010');
select pg_temp.esc_ok('helper makes someone owner of ESC Small'
    , 'select * from auth.create_owner(''esc'', {helper}, ''esc'', {target}, {g_small}, {esc})');
select pg_temp.esc_ok('the tenant owner appoints another tenant owner'
    , 'select * from auth.create_owner(''esc'', {owner}, ''esc'', {target}, null, {esc})');

do $$
begin
    perform pg_temp.esc_is('tenant owners'
        , (select string_agg(ui.username, ',' order by ui.username)
           from auth.owner o inner join auth.user_info ui on ui.user_id = o.user_id
           where o.tenant_id = pg_temp.esc('esc')::int and o.user_group_id is null)
        , 'esc_owner,esc_target,esc_target2');
end $$;

do $$
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit D-19: no privilege escalation - Finished';
    raise notice '=================================================================';
end $$;
