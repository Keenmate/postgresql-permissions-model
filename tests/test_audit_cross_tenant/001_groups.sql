set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Groups: tenant B's owner and admin call with A's group id and _tenant_id = B.
-- Every call raises 33011 (group not found) and A's group is unchanged.
-- ============================================================================
do $$
declare
    __actor text;
begin
    raise notice '';
    raise notice '--- 001: groups of tenant A, called with _tenant_id = B ---';

    foreach __actor in array array['owner_b_id', 'admin_b_id'] loop
        perform pg_temp.a02_expect(__actor || ' create_user_group_member',
            format('select * from auth.create_user_group_member(''t'', {%s}, ''c'', {ga_id}, {%s}, {b_id})', __actor, __actor), '33011');
        perform pg_temp.a02_expect(__actor || ' delete_user_group_member',
            format('select auth.delete_user_group_member(''t'', {%s}, ''c'', {ga_id}, {member_id}, {b_id})', __actor), '33011');
        perform pg_temp.a02_expect(__actor || ' create_owner (group)',
            format('select * from auth.create_owner(''t'', {%s}, ''c'', {%s}, {ga_id}, {b_id})', __actor, __actor), '33011');
        perform pg_temp.a02_expect(__actor || ' delete_owner (group)',
            format('select auth.delete_owner(''t'', {%s}, ''c'', {member_id}, {ga_id}, {b_id})', __actor), '33011');
    end loop;

    perform pg_temp.a02_expect('update_user_group',
        'select * from auth.update_user_group(''t'', {admin_b_id}, ''c'', {ga_id}, ''hijacked'', true, true, false, false, {b_id})', '33011');
    perform pg_temp.a02_expect('enable_user_group',  'select * from auth.enable_user_group(''t'', {admin_b_id}, ''c'', {ga_id}, {b_id})', '33011');
    perform pg_temp.a02_expect('disable_user_group', 'select * from auth.disable_user_group(''t'', {admin_b_id}, ''c'', {ga_id}, {b_id})', '33011');
    perform pg_temp.a02_expect('lock_user_group',    'select * from auth.lock_user_group(''t'', {admin_b_id}, ''c'', {ga_id}, {b_id})', '33011');
    perform pg_temp.a02_expect('unlock_user_group',  'select * from auth.unlock_user_group(''t'', {admin_b_id}, ''c'', {ga_id}, {b_id})', '33011');
    perform pg_temp.a02_expect('delete_user_group',  'select * from auth.delete_user_group(''t'', {admin_b_id}, ''c'', {ga_id}, {b_id})', '33011');
    perform pg_temp.a02_expect('set_user_group_as_external', 'select auth.set_user_group_as_external(''t'', {admin_b_id}, ''c'', {ga_id}, {b_id})', '33011');
    perform pg_temp.a02_expect('set_user_group_as_hybrid',   'select auth.set_user_group_as_hybrid(''t'', {admin_b_id}, ''c'', {ga_id}, {b_id})', '33011');
    perform pg_temp.a02_expect('set_user_group_as_internal', 'select auth.set_user_group_as_internal(''t'', {admin_b_id}, ''c'', {ga_id}, {b_id})', '33011');
    perform pg_temp.a02_expect('ensure_user_group_mapping',
        'select * from auth.ensure_user_group_mapping(''t'', {admin_b_id}, ''c'', {ga_id}, ''aad'', ''a02-object'', null, null, {b_id})', '33011');
    perform pg_temp.a02_expect('get_user_group_by_id',
        'select * from auth.get_user_group_by_id(''t'', {admin_b_id}, ''c'', {ga_id}, {b_id})', '33011');
    perform pg_temp.a02_expect('get_user_group_members',
        'select * from auth.get_user_group_members(''t'', {admin_b_id}, ''c'', {ga_id}, {b_id})', '33011');
    perform pg_temp.a02_expect('get_assigned_group_permissions',
        'select * from auth.get_assigned_group_permissions(''t'', {admin_b_id}, ''c'', {ga_id}, {b_id})', '33011');
end $$;

-- A's group and its membership are unchanged; nobody from B gained anything in A
do $$
declare
    __a        int    := pg_temp.a02('a_id')::int;
    __ga       int    := pg_temp.a02('ga_id')::int;
    __owner_b  bigint := pg_temp.a02('owner_b_id')::bigint;
    __admin_b  bigint := pg_temp.a02('admin_b_id')::bigint;
    __g        record;
begin
    select title, is_active, is_assignable, is_external from auth.user_group where user_group_id = __ga into __g;
    if __g.title is null then
        raise notice 'FAIL: A''s group was deleted';
    elsif __g.title = 'hijacked' or not __g.is_active or not __g.is_assignable or __g.is_external then
        raise notice 'FAIL: A''s group was changed (title %, active %, assignable %, external %)',
            __g.title, __g.is_active, __g.is_assignable, __g.is_external;
    else
        raise notice 'PASS: A''s group is unchanged';
    end if;

    if exists(select from auth.user_group_member where user_group_id = __ga and user_id in (__owner_b, __admin_b)) then
        raise notice 'FAIL: a tenant B user became a member of A''s group';
    else
        raise notice 'PASS: no tenant B user is a member of A''s group';
    end if;

    if exists(select from auth.user_group_member where user_group_id = __ga and user_id = pg_temp.a02('member_id')::bigint) then
        raise notice 'PASS: A''s existing member was not removed';
    else
        raise notice 'FAIL: A''s existing member was removed';
    end if;

    if exists(select from auth.owner where user_group_id = __ga) then
        raise notice 'FAIL: an owner row was created for A''s group';
    else
        raise notice 'PASS: no owner row for A''s group';
    end if;

    if auth.has_permission(__owner_b, 'c', 'tenants.update_tenant', __a, false)
        or auth.has_permission(__admin_b, 'c', 'tenants.update_tenant', __a, false) then
        raise notice 'FAIL: a tenant B user holds tenants.update_tenant in A';
    else
        raise notice 'PASS: no tenant B user holds tenants.update_tenant in A';
    end if;
end $$;

-- Own tenant still works: admin_b adds and removes a member of B's group
do $$
declare
    __b      int    := pg_temp.a02('b_id')::int;
    __gb     int    := pg_temp.a02('gb_id')::int;
    __admin  bigint := pg_temp.a02('admin_b_id')::bigint;
    __member bigint := pg_temp.a02('member_id')::bigint;
begin
    perform auth.create_user_group_member('t', __admin, 'c', __gb, __member, __b);
    if exists(select from auth.user_group_member where user_group_id = __gb and user_id = __member) then
        raise notice 'PASS: own tenant: member added to B''s group';
    else
        raise notice 'FAIL: own tenant: member not added to B''s group';
    end if;

    if (select g.__title from auth.get_user_group_by_id('t', __admin, 'c', __gb, __b) g) is not null then
        raise notice 'PASS: own tenant: get_user_group_by_id returns B''s group';
    else
        raise notice 'FAIL: own tenant: get_user_group_by_id returned nothing';
    end if;

    perform auth.delete_user_group_member('t', __admin, 'c', __gb, __member, __b);
    if not exists(select from auth.user_group_member where user_group_id = __gb and user_id = __member) then
        raise notice 'PASS: own tenant: member removed from B''s group';
    else
        raise notice 'FAIL: own tenant: member still in B''s group';
    end if;
end $$;
