set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   tenant T, tenant U : created the normal way (T with an owner)
--   in T, one user per way of belonging:
--     d03_admin    perm set d03_admin assigned directly (tenants/users/invitations)
--     d03_member   member of T's Tenant Members group
--     d03_direct   tenant_member perm set assigned directly, no group
--     d03_owner    tenant owner, nothing else
--     d03_res      a resource grant only
--     d03_role     a resource role only
--   not members of T:
--     d03_denied   a resource deny only
--     d03_inactive member of a disabled group of T only
--     d03_outsider member of U's Tenant Members group
--     d03_invitee  nothing yet (joins T by invitation in 003)
--   d03_sysadmin   full_admin in tenant 1
-- ============================================================================
create temp table if not exists _d03 (key text primary key, val bigint);

do $$
declare
    __t       int;
    __u       int;
    __ps_id   int;
    __off_g   int;
    __ids     jsonb := '{}';
    __name    text;
    __id      bigint;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit D-03: tenant membership - Starting';
    raise notice '=================================================================';

    foreach __name in array array['admin', 'member', 'direct', 'owner', 'res', 'role', 'denied', 'inactive',
                                  'outsider', 'invitee', 'sysadmin']
    loop
        insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, can_login)
        values ('d03', 'd03', 'normal', 'd03_' || __name, 'd03_' || __name, 'D03 ' || __name, 'd03_' || __name || '@test.com', true)
        returning user_id into __id;
        insert into _d03 values (__name, __id);
    end loop;

    select t.__tenant_id
    from auth.create_tenant('d03', 1, 'd03', 'D03 Tenant T', 'd03_t', _tenant_owner_id := (select val from _d03 where key = 'owner')) t
    into __t;
    select t.__tenant_id from auth.create_tenant('d03', 1, 'd03', 'D03 Tenant U', 'd03_u') t into __u;
    insert into _d03 values ('t', __t), ('u', __u);

    -- admin of T
    insert into auth.perm_set (created_by, updated_by, tenant_id, code, is_system, is_assignable)
    values ('d03', 'd03', __t, 'd03_admin', false, true)
    returning perm_set_id into __ps_id;
    insert into auth.perm_set_perm (created_by, perm_set_id, permission_id)
    select 'd03', __ps_id, p.permission_id
    from auth.permission p
    where subpath(p.full_code, 0, 1)::text in ('tenants', 'users', 'invitations');
    perform unsecure.assign_permission_as_system(null::integer, (select val from _d03 where key = 'admin'), 'd03_admin', null, __t);

    -- sysadmin in tenant 1
    perform unsecure.assign_permission_as_system(null::integer, (select val from _d03 where key = 'sysadmin'), 'full_admin', null, 1);

    -- group member, direct grant
    insert into auth.user_group_member (created_by, user_group_id, user_id, member_type_code)
    select 'd03', ug.user_group_id, (select val from _d03 where key = 'member'), 'manual'
    from auth.user_group ug where ug.tenant_id = __t and ug.code = 'tenant_members';
    perform unsecure.assign_permission_as_system(null::integer, (select val from _d03 where key = 'direct'), 'tenant_member', null, __t);

    -- resource grant, resource role, resource deny
    insert into const.resource_type (code, source, path, key_schema) values ('d03_doc', 'd03', 'd03_doc', '{"doc": "int"}');
    insert into const.resource_type_flag (resource_type_code, access_flag_code) values ('d03_doc', 'read');
    perform unsecure.ensure_resource_access_partition('d03_doc');
    insert into const.resource_role (code, resource_type, is_active, source) values ('d03_reader', 'd03_doc', true, 'd03');
    insert into const.resource_role_flag (resource_role_code, access_flag_code) values ('d03_reader', 'read');

    insert into auth.resource_access (created_by, updated_by, tenant_id, resource_type, root_type, resource_id, resource_path, user_id, user_group_id, access_flag, is_deny) values
        ('d03', 'd03', __t, 'd03_doc', 'd03_doc', '{"doc":1}', null, (select val from _d03 where key = 'res'),    null, 'read', false),
        ('d03', 'd03', __t, 'd03_doc', 'd03_doc', '{"doc":1}', null, (select val from _d03 where key = 'denied'), null, 'read', true);
    insert into auth.resource_role_assignment (created_by, updated_by, tenant_id, resource_type, root_type, resource_id, resource_path, user_id, user_group_id, role_code) values
        ('d03', 'd03', __t, 'd03_doc', 'd03_doc', '{"doc":2}', null, (select val from _d03 where key = 'role'), null, 'd03_reader');

    -- member of a disabled group of T only
    insert into auth.user_group (created_by, updated_by, tenant_id, title, code, is_assignable, is_active, is_external, is_system)
    values ('d03', 'd03', __t, 'D03 Off', 'd03_off', true, false, false, false)
    returning user_group_id into __off_g;
    insert into auth.user_group_member (created_by, user_group_id, user_id, member_type_code)
    values ('d03', __off_g, (select val from _d03 where key = 'inactive'), 'manual');

    -- member of U only
    insert into auth.user_group_member (created_by, user_group_id, user_id, member_type_code)
    select 'd03', ug.user_group_id, (select val from _d03 where key = 'outsider'), 'manual'
    from auth.user_group ug where ug.tenant_id = __u and ug.code = 'tenant_members';

    raise notice 'PASS: setup (T=%, U=%)', __t, __u;
end $$;

-- members of T expected by every read
create temp table if not exists _d03_expected (username text primary key);
insert into _d03_expected values ('d03_admin'), ('d03_member'), ('d03_direct'), ('d03_owner'), ('d03_res'), ('d03_role');

create or replace function pg_temp.d03_check(_what text, _actual text[]) returns void
    language plpgsql
as
$$
declare
    __expected text[] := (select array_agg(username order by username) from _d03_expected);
    __got      text[] := (select coalesce(array_agg(a order by a), '{}') from unnest(_actual) a where a like 'd03\_%');
begin
    if __got = __expected then
        raise notice 'PASS: % lists exactly the members of T', _what;
    else
        raise notice 'FAIL: % - expected %, got %', _what, __expected, __got;
    end if;
end;
$$;
