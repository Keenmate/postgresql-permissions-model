set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Resources: an owner sees every resource of their tenant, but only while
-- active, not locked and the tenant is live; never in another tenant.
-- Group owners: member management of their own group only.
-- ============================================================================
do $$
declare
    __a     int    := pg_temp.d05('a_id')::int;
    __b     int    := pg_temp.d05('b_id')::int;
    __owner bigint := pg_temp.d05('owner_a_id')::bigint;
begin
    raise notice '';
    raise notice '--- 002: owner resource access, group owners ---';

    perform pg_temp.d05_check('owner: any resource of A',
        auth.has_resource_access(__owner, 'c', 'd05_doc', '{"id": 1}', 'read', __a, false), true);
    perform pg_temp.d05_check('owner: no resource of B',
        auth.has_resource_access(__owner, 'c', 'd05_doc', '{"id": 1}', 'read', __b, false), false);

    update auth.user_info set is_locked = true where user_id = __owner;
    perform pg_temp.d05_check('locked owner: no resource of A',
        auth.has_resource_access(__owner, 'c', 'd05_doc', '{"id": 1}', 'read', __a, false), false);
    update auth.user_info set is_locked = false, is_active = false where user_id = __owner;
    perform pg_temp.d05_check('disabled owner: no resource of A',
        auth.has_resource_access(__owner, 'c', 'd05_doc', '{"id": 1}', 'read', __a, false), false);
    update auth.user_info set is_active = true where user_id = __owner;

    update auth.tenant set deleted_at = now() where tenant_id = __a;
    perform pg_temp.d05_check('owner of a soft-deleted tenant: no resource of A',
        auth.has_resource_access(__owner, 'c', 'd05_doc', '{"id": 1}', 'read', __a, false), false);
    update auth.tenant set deleted_at = null where tenant_id = __a;

    perform pg_temp.d05_check('owner restored: any resource of A again',
        auth.has_resource_access(__owner, 'c', 'd05_doc', '{"id": 1}', 'read', __a, false), true);
end $$;

do $$
declare
    __a           int    := pg_temp.d05('a_id')::int;
    __gowner      bigint := pg_temp.d05('group_owner_id')::bigint;
    __member      bigint := pg_temp.d05('member_id')::bigint;
    __group       int    := pg_temp.d05('ga_members_id')::int;
    __admin_group int;
    __state       text;
begin
    -- own group: member management works
    perform auth.create_user_group_member('t', __gowner, 'c', __group, __member, __a);
    perform pg_temp.d05_check('group owner adds a member to their group',
        exists(select from auth.user_group_member where user_group_id = __group and user_id = __member), true);

    -- another group of the tenant (which has no owner): needs the permission
    select user_group_id from auth.user_group where tenant_id = __a and code = 'tenant_admins' into __admin_group;
    begin
        perform auth.create_user_group_member('t', __gowner, 'c', __admin_group, __gowner, __a);
        __state := 'none';
    exception when others then
        __state := sqlstate;
    end;
    perform pg_temp.d05_check('group owner cannot add members to another group (32001)', __state = '32001', true);

    -- appointing more owners is not member management
    begin
        perform auth.create_owner('t', __gowner, 'c', __member, __group, __a);
        __state := 'none';
    exception when others then
        __state := sqlstate;
    end;
    perform pg_temp.d05_check('group owner cannot appoint group owners (32001)', __state = '32001', true);

    perform pg_temp.d05_check('group owner holds no tenant permissions',
        auth.has_permission(__gowner, 'c', 'groups.create_group', __a, false), false);
end $$;
