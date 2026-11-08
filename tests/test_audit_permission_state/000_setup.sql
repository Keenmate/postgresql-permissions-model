set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP (all in tenant B, one test permission 'audit04_perm')
--   u_group  : manual member of group G, G holds the permission
--   u_direct : permission assigned directly
--   u_mapped : identity on provider audit04_idp with claim 'audit04-grp', mapped
--              to group GM which holds the permission (membership is created by
--              the first permission check)
--   owner_b  : tenant-wide owner of B, no permissions
-- ============================================================================
do $$
declare
    __b_id      int;
    __perm      text;
    __g_id      int;
    __gm_id     int;
    __u_group   bigint;
    __u_direct  bigint;
    __u_mapped  bigint;
    __owner_b   bigint;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit 04: disabled and deleted state removes access - Starting';
    raise notice '=================================================================';

    select t.__tenant_id from auth.create_tenant('audit04', 1, 'audit04-setup', 'Audit04 Tenant B', 'audit04_b') t
    into __b_id;

    select p.full_code::text from unsecure.create_permission_as_system('Audit04 perm', '', true) p into __perm;

    insert into auth.user_group (created_by, updated_by, tenant_id, title, code, is_assignable, is_active, is_external, is_system)
    values ('audit04', 'audit04', __b_id, 'Audit04 G', 'audit04_g', true, true, false, false)
    returning user_group_id into __g_id;
    insert into auth.user_group (created_by, updated_by, tenant_id, title, code, is_assignable, is_active, is_external, is_system)
    values ('audit04', 'audit04', __b_id, 'Audit04 GM', 'audit04_gm', true, true, true, false)
    returning user_group_id into __gm_id;

    perform unsecure.assign_permission_as_system(__g_id, null, null, __perm, __b_id);
    perform unsecure.assign_permission_as_system(__gm_id, null, null, __perm, __b_id);

    insert into auth.provider (created_by, updated_by, code, is_active, allows_group_mapping)
    values ('audit04', 'audit04', 'audit04_idp', true, true);
    insert into auth.user_group_mapping (created_by, user_group_id, provider_code, mapped_object_id, mapped_object_name)
    values ('audit04', __gm_id, 'audit04_idp', 'audit04-grp', 'Audit04 group');

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('audit04', 'audit04', 'normal', 'audit04_u_group', 'audit04_u_group', 'U group', true)
    returning user_id into __u_group;
    insert into auth.user_group_member (created_by, user_group_id, user_id, member_type_code)
    values ('audit04', __g_id, __u_group, 'manual');

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('audit04', 'audit04', 'normal', 'audit04_u_direct', 'audit04_u_direct', 'U direct', true)
    returning user_id into __u_direct;
    perform unsecure.assign_permission_as_system(null::integer, __u_direct, null, __perm, __b_id);

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login, last_used_provider_code)
    values ('audit04', 'audit04', 'normal', 'audit04_u_mapped', 'audit04_u_mapped', 'U mapped', true, 'audit04_idp')
    returning user_id into __u_mapped;
    insert into auth.user_identity (created_by, updated_by, provider_code, user_id, uid, provider_oid, is_active, provider_groups)
    values ('audit04', 'audit04', 'audit04_idp', __u_mapped, 'uid-audit04-mapped', 'oid-audit04-mapped', true, array ['audit04-grp']);

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('audit04', 'audit04', 'normal', 'audit04_owner_b', 'audit04_owner_b', 'Owner B', true)
    returning user_id into __owner_b;
    insert into auth.owner (created_by, tenant_id, user_group_id, user_id) values ('audit04', __b_id, null, __owner_b);

    create temp table if not exists _a04 (key text primary key, val text);
    delete from _a04;
    insert into _a04 values
        ('b_id', __b_id::text), ('perm', __perm), ('g_id', __g_id::text), ('gm_id', __gm_id::text),
        ('u_group', __u_group::text), ('u_direct', __u_direct::text), ('u_mapped', __u_mapped::text), ('owner_b', __owner_b::text);

    raise notice 'SETUP: B=%, perm=%, G=%, GM=%, u_group=%, u_direct=%, u_mapped=%, owner_b=%',
        __b_id, __perm, __g_id, __gm_id, __u_group, __u_direct, __u_mapped, __owner_b;
end $$;

-- silent check helper for this suite; the owner is checked on a permission of the
-- tenant_owner perm set (owners hold that set, not arbitrary permissions - v2.12)
create or replace function pg_temp.a04_can(_who text) returns boolean
    language sql
as $$
select auth.has_permission((select val::bigint from _a04 where key = _who), 'audit04',
                           case when _who = 'owner_b' then 'groups.create_group'
                                else (select val from _a04 where key = 'perm') end,
                           (select val::int from _a04 where key = 'b_id'), false);
$$;
