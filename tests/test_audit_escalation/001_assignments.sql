set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Assigning and unassigning permissions and perm sets
-- ============================================================================
do $$
declare
    __a bigint;
begin
    raise notice 'TEST 1: assign only what you hold';

    -- given by the system, for the unassign checks
    select a.assignment_id from unsecure.assign_permission('esc', 1, 'esc', null, pg_temp.esc('target2')::bigint
        , 'tenant_admin', _tenant_id := pg_temp.esc('esc')::int) a into __a;
    insert into _esc values ('a_admin', __a);
    select a.assignment_id from unsecure.assign_permission('esc', 1, 'esc', null, pg_temp.esc('target2')::bigint
        , 'small', _tenant_id := pg_temp.esc('esc')::int) a into __a;
    insert into _esc values ('a_small', __a);
end $$;

select pg_temp.esc_expect('helper assigns the tenant_admin perm set to a user'
    , 'select * from auth.assign_permission(''esc'', {helper}, ''esc'', null, {target}, ''tenant_admin'', null, {esc})', '32010');
select pg_temp.esc_expect('helper assigns a perm set with a permission they lack'
    , 'select * from auth.assign_permission(''esc'', {helper}, ''esc'', null, {target}, ''elevated'', null, {esc})', '32010');
select pg_temp.esc_expect('helper assigns a permission they lack'
    , 'select * from auth.assign_permission(''esc'', {helper}, ''esc'', null, {target}, null, ''tenants.update_tenant'', {esc})', '32010');
select pg_temp.esc_expect('helper assigns an ancestor of a permission they hold'
    , 'select * from auth.assign_permission(''esc'', {helper}, ''esc'', null, {target}, null, ''users'', {esc})', '32010');
select pg_temp.esc_expect('helper assigns tenant_admin to a group'
    , 'select * from auth.assign_permission(''esc'', {helper}, ''esc'', {g_small}, null, ''tenant_admin'', null, {esc})', '32010');
select pg_temp.esc_expect('helper gives themselves tenant_owner'
    , 'select * from auth.assign_permission(''esc'', {helper}, ''esc'', null, {helper}, ''tenant_owner'', null, {esc})', '32010');

select pg_temp.esc_ok('helper assigns a perm set they hold'
    , 'select * from auth.assign_permission(''esc'', {helper}, ''esc'', null, {target}, ''small'', null, {esc})');
select pg_temp.esc_ok('helper assigns a permission they hold'
    , 'select * from auth.assign_permission(''esc'', {helper}, ''esc'', null, {target}, null, ''users.read_users'', {esc})');
select pg_temp.esc_ok('helper assigns a descendant of a node they hold (journal)'
    , 'select * from auth.assign_permission(''esc'', {helper}, ''esc'', null, {target}, null, ''journal.read_journal'', {esc})');
select pg_temp.esc_ok('helper assigns their own Helpdesk set'
    , 'select * from auth.assign_permission(''esc'', {helper}, ''esc'', {g_small}, null, ''helpdesk'', null, {esc})');

select pg_temp.esc_expect('helper unassigns tenant_admin'
    , 'select * from auth.unassign_permission(''esc'', {helper}, ''esc'', {a_admin}, {esc})', '32010');
select pg_temp.esc_ok('helper unassigns a set they hold'
    , 'select * from auth.unassign_permission(''esc'', {helper}, ''esc'', {a_small}, {esc})');

do $$
begin
    perform pg_temp.esc_is('target got nothing of tenant_admin'
        , (select string_agg(coalesce(ps.code, p.full_code::text), ',' order by coalesce(ps.code, p.full_code::text))
           from auth.permission_assignment pa
                    left join auth.perm_set ps on ps.perm_set_id = pa.perm_set_id
                    left join auth.permission p on p.permission_id = pa.permission_id
           where pa.user_id = pg_temp.esc('target')::bigint)
        , 'journal.read_journal,small,users.read_users');
    perform pg_temp.esc_is('target2 still has tenant_admin, not small'
        , (select string_agg(ps.code, ',' order by ps.code)
           from auth.permission_assignment pa
                    inner join auth.perm_set ps on ps.perm_set_id = pa.perm_set_id
           where pa.user_id = pg_temp.esc('target2')::bigint)
        , 'tenant_admin');
end $$;

-- ============================================================================
-- Exemptions: tenant owners and user 1
-- ============================================================================
do $$
begin
    raise notice 'TEST 2: tenant owners and user 1 are exempt';
end $$;

select pg_temp.esc_ok('the tenant owner assigns tenant_admin'
    , 'select * from auth.assign_permission(''esc'', {owner}, ''esc'', null, {target}, ''tenant_admin'', null, {esc})');
select pg_temp.esc_ok('user 1 assigns elevated'
    , 'select * from auth.assign_permission(''esc'', 1, ''esc'', null, {target}, ''elevated'', null, {esc})');
