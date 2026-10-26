set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   tenant 1 : admin (full_admin perm set, NOT user 1 — user 1 bypasses every
--              check), plain user owning one group, active group, inactive group
--   tenant B : group, permission assignment and group mapping the tenant-1 admin
--              must not be able to touch
-- ============================================================================
do $$
declare
    __admin_id          bigint;
    __plain_id          bigint;
    __tenant_b_id       int;
    __group_a_id        int;
    __group_inactive_id int;
    __group_b_id        int;
    __assignment_b_id   bigint;
    __mapping_b_id      int;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Tenant scoping & ownership security - Starting';
    raise notice '=================================================================';

    insert into auth.provider (created_by, updated_by, code, is_active, allows_group_mapping)
    values ('tss_test', 'tss_test', 'tss_prov', true, true);

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, can_login)
    values ('tss_test', 'tss_test', 'normal', 'tss_admin', 'tss_admin', 'TSS Admin', 'tss_admin@test.com', true)
    returning user_id into __admin_id;

    perform unsecure.assign_permission_as_system(null::integer, __admin_id, 'full_admin');

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, can_login)
    values ('tss_test', 'tss_test', 'normal', 'tss_plain', 'tss_plain', 'TSS Plain', 'tss_plain@test.com', true)
    returning user_id into __plain_id;

    insert into auth.tenant (created_by, updated_by, title, code)
    values ('tss_test', 'tss_test', 'TSS Tenant B', 'tss_tenant_b')
    returning tenant_id into __tenant_b_id;

    insert into auth.user_group (created_by, updated_by, tenant_id, title, code, is_assignable, is_active, is_external, is_system)
    values ('tss_test', 'tss_test', 1, 'TSS Group A', 'tss_group_a', true, true, false, false)
    returning user_group_id into __group_a_id;

    insert into auth.user_group (created_by, updated_by, tenant_id, title, code, is_assignable, is_active, is_external, is_system)
    values ('tss_test', 'tss_test', 1, 'TSS Group Inactive', 'tss_group_inactive', true, false, false, false)
    returning user_group_id into __group_inactive_id;

    insert into auth.user_group (created_by, updated_by, tenant_id, title, code, is_assignable, is_active, is_external, is_system)
    values ('tss_test', 'tss_test', __tenant_b_id, 'TSS Group B', 'tss_group_b', true, true, false, false)
    returning user_group_id into __group_b_id;

    insert into auth.permission_assignment (created_by, tenant_id, user_id, permission_id)
    values ('tss_test', __tenant_b_id, __plain_id,
            (select permission_id from auth.permission where is_assignable order by permission_id limit 1))
    returning assignment_id into __assignment_b_id;

    insert into auth.user_group_mapping (created_by, user_group_id, provider_code, mapped_object_id, mapped_object_name)
    values ('tss_test', __group_b_id, 'tss_prov', 'tss-b-object', 'TSS B object')
    returning user_group_mapping_id into __mapping_b_id;

    -- plain user owns only group A — not the tenant
    insert into auth.owner (created_by, tenant_id, user_group_id, user_id)
    values ('tss_test', 1, __group_a_id, __plain_id);

    create temp table if not exists _tss (key text primary key, val text);
    delete from _tss;
    insert into _tss values
        ('admin_id', __admin_id::text), ('plain_id', __plain_id::text),
        ('tenant_b_id', __tenant_b_id::text), ('group_a_id', __group_a_id::text),
        ('group_inactive_id', __group_inactive_id::text), ('group_b_id', __group_b_id::text),
        ('assignment_b_id', __assignment_b_id::text), ('mapping_b_id', __mapping_b_id::text);

    raise notice 'SETUP: admin=%, plain=%, tenant_b=%, group_a=%, group_b=%', __admin_id, __plain_id, __tenant_b_id, __group_a_id, __group_b_id;
end $$;
