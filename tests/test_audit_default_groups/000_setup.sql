set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   provider dg_aad (group mapping allowed)
--   tenant B, owned by dg_owner; group "B Everyone" with the tenant_member perm set
--   dg_owner tries to make "B Everyone" a default group through auth.update_user_group
--   (possible only while the flag exists, i.e. before v2.20)
-- ============================================================================
create temp table if not exists _dg (key text primary key, val bigint);

do $$
declare
    __owner bigint;
    __b     int;
    __g     int;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit D-13: default groups - Starting';
    raise notice '=================================================================';

    insert into auth.provider (created_by, updated_by, code, is_active, allows_group_mapping, allows_group_sync)
    values ('dg', 'dg', 'dg_aad', true, true, false);

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, can_login)
    values ('dg', 'dg', 'normal', 'dg_owner', 'dg_owner', 'DG owner', 'dg_owner@test.com', true)
    returning user_id into __owner;

    select t.__tenant_id from auth.create_tenant('dg', 1, 'dg', 'DG Tenant B', 'dg_b', _tenant_owner_id := __owner) t into __b;

    select g.__user_group_id from auth.create_user_group('dg', __owner, 'dg', 'B Everyone', _tenant_id := __b) g into __g;
    perform unsecure.assign_permission('dg', 1, 'dg', __g, null, 'tenant_member', _tenant_id := __b);

    insert into _dg values ('owner', __owner), ('b', __b), ('g', __g);

    if exists(select from information_schema.columns
              where table_schema = 'auth' and table_name = 'user_group' and column_name = 'is_default') then
        execute format('select * from auth.update_user_group(%L, %s, %L, %s, %L, true, true, false, true, %s)'
            , 'dg', __owner, 'dg', __g, 'B Everyone', __b);
        raise notice 'SETUP: is_default still exists, the owner of B marked "B Everyone" as default';
    end if;

    raise notice 'PASS: setup (B=%, group=%)', __b, __g;
end $$;
