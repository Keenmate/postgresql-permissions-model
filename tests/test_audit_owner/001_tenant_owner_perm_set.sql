set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- A tenant owner holds the tenant_owner perm set of their tenant: run-own-
-- tenant permissions, cached and visible; nothing global, nothing elsewhere.
-- ============================================================================
do $$
declare
    __a     int    := pg_temp.d05('a_id')::int;
    __b     int    := pg_temp.d05('b_id')::int;
    __owner bigint := pg_temp.d05('owner_a_id')::bigint;
begin
    raise notice '';
    raise notice '--- 001: tenant owner = tenant_owner perm set ---';

    perform pg_temp.d05_check('every tenant has a tenant_owner perm set (A)',
        exists(select from auth.perm_set where tenant_id = __a and code = 'tenant_owner'), true);
    perform pg_temp.d05_check('every tenant has a tenant_owner perm set (B)',
        exists(select from auth.perm_set where tenant_id = __b and code = 'tenant_owner'), true);

    -- run-own-tenant permissions
    perform pg_temp.d05_check('owner: groups.create_group in A',          auth.has_permission(__owner, 'c', 'groups.create_group', __a, false), true);
    perform pg_temp.d05_check('owner: permissions.assign_permission in A', auth.has_permission(__owner, 'c', 'permissions.assign_permission', __a, false), true);
    perform pg_temp.d05_check('owner: invitations.create_invitation in A', auth.has_permission(__owner, 'c', 'invitations.create_invitation', __a, false), true);
    perform pg_temp.d05_check('owner: api_keys.create_api_key in A',       auth.has_permission(__owner, 'c', 'api_keys.create_api_key', __a, false), true);
    perform pg_temp.d05_check('owner: tenants.update_tenant in A',         auth.has_permission(__owner, 'c', 'tenants.update_tenant', __a, false), true);

    -- the grant is an ordinary cache row, visible like any other
    perform pg_temp.d05_check('owner: tenant_owner permissions are in the permission cache',
        exists(select from auth.user_permission_cache
               where user_id = __owner and tenant_id = __a and 'groups.create_group' = any (permissions)), true);

    -- nothing global, nothing cross-tenant
    perform pg_temp.d05_check('owner: no tenants.create_tenant in A',      auth.has_permission(__owner, 'c', 'tenants.create_tenant', __a, false), false);
    perform pg_temp.d05_check('owner: no providers.create_provider in A',  auth.has_permission(__owner, 'c', 'providers.create_provider', __a, false), false);
    perform pg_temp.d05_check('owner: no users.read_all_users in A',       auth.has_permission(__owner, 'c', 'users.read_all_users', __a, false), false);
    perform pg_temp.d05_check('owner: no permissions.create_permission in A', auth.has_permission(__owner, 'c', 'permissions.create_permission', __a, false), false);
    perform pg_temp.d05_check('owner: no users.lock_user in A',            auth.has_permission(__owner, 'c', 'users.lock_user', __a, false), false);
    perform pg_temp.d05_check('owner: nothing in B',                       auth.has_permission(__owner, 'c', 'groups.create_group', __b, false), false);
end $$;

-- Owner manages members through the perm set (no shortcut needed)
do $$
declare
    __a      int    := pg_temp.d05('a_id')::int;
    __owner  bigint := pg_temp.d05('owner_a_id')::bigint;
    __member bigint := pg_temp.d05('member_id')::bigint;
    __group  int;
begin
    select user_group_id from auth.user_group where tenant_id = __a and code = 'tenant_admins' into __group;
    perform auth.create_user_group_member('t', __owner, 'c', __group, __member, __a);
    perform pg_temp.d05_check('owner adds a member to A''s tenant_admins',
        exists(select from auth.user_group_member where user_group_id = __group and user_id = __member), true);
    perform auth.delete_user_group_member('t', __owner, 'c', __group, __member, __a);
end $$;

-- Ownership removed = permissions gone at the next check
do $$
declare
    __a     int    := pg_temp.d05('a_id')::int;
    __owner bigint := pg_temp.d05('owner_a_id')::bigint;
begin
    perform auth.has_permission(__owner, 'c', 'groups.create_group', __a, false);  -- warm the cache
    delete from auth.owner where user_id = __owner and tenant_id = __a and user_group_id is null;
    perform pg_temp.d05_check('former owner: no groups.create_group in A',
        auth.has_permission(__owner, 'c', 'groups.create_group', __a, false), false);
    insert into auth.owner (created_by, tenant_id, user_group_id, user_id) values ('auditd05', __a, null, __owner);
    perform pg_temp.d05_check('owner again: groups.create_group in A',
        auth.has_permission(__owner, 'c', 'groups.create_group', __a, false), true);
end $$;

-- Changing the tenant_owner perm set reaches owners at once
do $$
declare
    __a     int    := pg_temp.d05('a_id')::int;
    __owner bigint := pg_temp.d05('owner_a_id')::bigint;
    __ps    int;
begin
    select perm_set_id from auth.perm_set where tenant_id = __a and code = 'tenant_owner' into __ps;
    perform auth.has_permission(__owner, 'c', 'groups.lock_group', __a, false);  -- warm the cache
    perform unsecure.delete_perm_set_permissions('t', 1, 'c', __ps, array ['groups.lock_group'], __a);
    perform pg_temp.d05_check('tenant_owner set without lock_group: owner loses it',
        auth.has_permission(__owner, 'c', 'groups.lock_group', __a, false), false);
end $$;
