set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Perm set edits: add or remove only what you hold
-- ============================================================================
do $$
begin
    raise notice 'TEST 3: perm set edits';
end $$;

select pg_temp.esc_expect('helper creates a perm set with a permission they lack'
    , 'select * from auth.create_perm_set(''esc'', {helper}, ''esc'', ''Sneaky'', _permissions := array[''tenants.update_tenant''], _tenant_id := {esc})', '32010');
select pg_temp.esc_expect('helper adds a permission they lack to a set'
    , 'select * from auth.create_perm_set_permissions(''esc'', {helper}, ''esc'', {ps_small}, array[''tenants.update_tenant''], {esc})', '32010');
select pg_temp.esc_expect('helper removes a permission they lack from a set'
    , 'select * from auth.delete_perm_set_permissions(''esc'', {helper}, ''esc'', {ps_elevated}, array[''tenants.update_tenant''], {esc})', '32010');
select pg_temp.esc_expect('helper switches assignability of a set they don''t hold'
    , 'select * from auth.update_perm_set(''esc'', {helper}, ''esc'', {ps_elevated}, ''Elevated'', false, {esc})', '32010');
select pg_temp.esc_expect('ensure_perm_sets adds a permission the caller lacks'
    , 'select * from auth.ensure_perm_sets(''esc'', {helper}, ''esc'', ''[{"title": "Small", "permissions": ["users.read_users", "tenants.update_tenant"]}]'', _tenant_id := {esc})', '32010');

select pg_temp.esc_ok('helper creates a perm set with a permission they hold'
    , 'select * from auth.create_perm_set(''esc'', {helper}, ''esc'', ''Readers'', _permissions := array[''users.read_users''], _tenant_id := {esc})');
select pg_temp.esc_ok('helper adds a permission they hold to a set'
    , 'select * from auth.create_perm_set_permissions(''esc'', {helper}, ''esc'', {ps_elevated}, array[''journal.read_journal''], {esc})');
select pg_temp.esc_ok('helper renames a set without changing its assignability'
    , 'select * from auth.update_perm_set(''esc'', {helper}, ''esc'', {ps_elevated}, ''Elevated renamed'', true, {esc})');

do $$
begin
    perform pg_temp.esc_is('Elevated still holds only what was allowed'
        , (select string_agg(p.full_code::text, ',' order by p.full_code::text)
           from auth.perm_set_perm psp inner join auth.permission p on p.permission_id = psp.permission_id
           where psp.perm_set_id = pg_temp.esc('ps_elevated')::int)
        , 'journal.read_journal,tenants.update_tenant');
    perform pg_temp.esc_is('Small got nothing new'
        , (select string_agg(p.full_code::text, ',' order by p.full_code::text)
           from auth.perm_set_perm psp inner join auth.permission p on p.permission_id = psp.permission_id
           where psp.perm_set_id = pg_temp.esc('ps_small')::int)
        , 'users.read_users');
end $$;

-- ============================================================================
-- Group members: you must hold the group's permissions; group owners may add anyway
-- ============================================================================
do $$
begin
    raise notice 'TEST 4: group members';
    perform unsecure.create_user_group_member('esc', 1, 'esc', pg_temp.esc('g_admins')::int, pg_temp.esc('target2')::bigint
        , pg_temp.esc('esc')::int);
end $$;

select pg_temp.esc_expect('helper adds a member to ESC Admins'
    , 'select * from auth.create_user_group_member(''esc'', {helper}, ''esc'', {g_admins}, {target}, {esc})', '32010');
select pg_temp.esc_expect('helper adds themselves to ESC Admins'
    , 'select * from auth.create_user_group_member(''esc'', {helper}, ''esc'', {g_admins}, {helper}, {esc})', '32010');
select pg_temp.esc_expect('helper removes a member from ESC Admins'
    , 'select auth.delete_user_group_member(''esc'', {helper}, ''esc'', {g_admins}, {target2}, {esc})', '32010');
select pg_temp.esc_ok('helper adds a member to ESC Small'
    , 'select * from auth.create_user_group_member(''esc'', {helper}, ''esc'', {g_small}, {target}, {esc})');
select pg_temp.esc_ok('the group owner adds a member to ESC Admins'
    , 'select * from auth.create_user_group_member(''esc'', {gowner}, ''esc'', {g_admins}, {target}, {esc})');
select pg_temp.esc_ok('the group owner removes a member from ESC Admins'
    , 'select auth.delete_user_group_member(''esc'', {gowner}, ''esc'', {g_admins}, {target}, {esc})');

-- ============================================================================
-- Group mappings and rule mappings
-- ============================================================================
do $$
declare
    __m int;
begin
    raise notice 'TEST 5: group mappings';
    insert into auth.user_group_mapping (created_by, user_group_id, provider_code, mapped_object_id)
    values ('esc', pg_temp.esc('g_admins')::int, 'esc_aad', 'admins')
    returning user_group_mapping_id into __m;
    insert into _esc values ('m_admins', __m);
end $$;

select pg_temp.esc_expect('helper maps an Azure group to ESC Admins'
    , 'select * from auth.create_user_group_mapping(''esc'', {helper}, ''esc'', {g_admins}, ''esc_aad'', ''everyone'', _tenant_id := {esc})', '32010');
select pg_temp.esc_expect('helper puts a rule mapping on ESC Admins'
    , 'select * from auth.create_user_group_rule_mapping(''esc'', {helper}, ''esc'', {g_admins}, _rule := ''{"mode": "always"}'', _tenant_id := {esc})', '32010');
select pg_temp.esc_expect('ensure_user_group_mappings on ESC Admins'
    , 'select * from auth.ensure_user_group_mappings(''esc'', {helper}, ''esc'', jsonb_build_array(jsonb_build_object(''user_group_id'', {g_admins}, ''provider_code'', ''esc_aad'', ''mapped_object_id'', ''everyone'')), {esc})', '32010');
select pg_temp.esc_expect('helper deletes the mapping of ESC Admins'
    , 'select auth.delete_user_group_mapping(''esc'', {helper}, ''esc'', {m_admins}, {esc})', '32010');
select pg_temp.esc_ok('helper maps an Azure group to ESC Small'
    , 'select * from auth.create_user_group_mapping(''esc'', {helper}, ''esc'', {g_small}, ''esc_aad'', ''readers'', _tenant_id := {esc})');
select pg_temp.esc_ok('helper puts a rule mapping on ESC Small'
    , 'select * from auth.create_user_group_rule_mapping(''esc'', {helper}, ''esc'', {g_small}, _rule := ''{"mode": "always"}'', _tenant_id := {esc})');

-- ============================================================================
-- Editing a shared rule: you must hold the permissions of every group using it
-- ============================================================================
do $$
declare
    __r int;
begin
    raise notice 'TEST 6: shared rules';
    insert into auth.rule (created_by, updated_by, tenant_id, code, title, rule)
    values ('esc', 'esc', pg_temp.esc('esc')::int, 'esc_admins_rule', 'ESC admins rule', '{"mode": "never"}')
    returning rule_id into __r;
    insert into _esc values ('rule_admins', __r);
    insert into auth.user_group_mapping (created_by, user_group_id, rule_id) values ('esc', pg_temp.esc('g_admins')::int, __r);

    insert into auth.rule (created_by, updated_by, tenant_id, code, title, rule)
    values ('esc', 'esc', pg_temp.esc('esc')::int, 'esc_small_rule', 'ESC small rule', '{"mode": "never"}')
    returning rule_id into __r;
    insert into _esc values ('rule_small', __r);
    insert into auth.user_group_mapping (created_by, user_group_id, rule_id) values ('esc', pg_temp.esc('g_small')::int, __r);
end $$;

select pg_temp.esc_expect('helper opens the rule ESC Admins uses to everyone'
    , 'select * from auth.update_rule(''esc'', {helper}, ''esc'', {rule_admins}, ''x'', ''{"mode": "always"}'', _tenant_id := {esc})', '32010');
select pg_temp.esc_ok('helper edits the rule ESC Small uses'
    , 'select * from auth.update_rule(''esc'', {helper}, ''esc'', {rule_small}, ''x'', ''{"mode": "always"}'', _tenant_id := {esc})');

do $$
begin
    perform pg_temp.esc_is('the admins rule is unchanged'
        , (select rule ->> 'mode' from auth.rule where rule_id = pg_temp.esc('rule_admins')::int), 'never');
    perform pg_temp.esc_is('nobody new in ESC Admins'
        , (select string_agg(ui.username, ',' order by ui.username)
           from auth.user_group_member m inner join auth.user_info ui on ui.user_id = m.user_id
           where m.user_group_id = pg_temp.esc('g_admins')::int)
        , 'esc_target2');
end $$;
