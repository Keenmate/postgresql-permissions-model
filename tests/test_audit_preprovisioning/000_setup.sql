set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP (provisioning as system)
--   providers p18_aad (group mapping) and p18_google
--   ABC : Tenant Members <- Azure abc
--   CDE : Tenant Admins with individual members only
--   FGH : Tenant Members <- Azure fgh + Azure abc
--         Tenant Admins  <- Azure fghadmins + individual members
--   svc_registrator (2) pre-provisions, svc_authenticator (3) logs users in
-- ============================================================================
create temp table if not exists _p18 (key text primary key, val bigint);

do $$
declare
    __abc int;
    __cde int;
    __fgh int;
    __g   int;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit: pre-provisioned users - Starting';
    raise notice '=================================================================';

    insert into auth.provider (created_by, updated_by, code, is_active, allows_group_mapping)
    values ('p18', 'p18', 'p18_aad', true, true), ('p18', 'p18', 'p18_google', true, false);

    select t.__tenant_id from auth.create_tenant('p18', 1, 'p18', 'P18 ABC', 'p18_abc') t into __abc;
    select t.__tenant_id from auth.create_tenant('p18', 1, 'p18', 'P18 CDE', 'p18_cde') t into __cde;
    select t.__tenant_id from auth.create_tenant('p18', 1, 'p18', 'P18 FGH', 'p18_fgh') t into __fgh;
    insert into _p18 values ('abc', __abc), ('cde', __cde), ('fgh', __fgh);

    select user_group_id from auth.user_group where tenant_id = __abc and code = 'tenant_members' into __g;
    perform auth.set_user_group_as_hybrid('p18', 1, 'p18', __g, __abc);
    perform auth.create_user_group_mapping('p18', 1, 'p18', __g, 'p18_aad', 'abc', 'Azure ABC', _tenant_id := __abc);

    select user_group_id from auth.user_group where tenant_id = __cde and code = 'tenant_admins' into __g;
    insert into _p18 values ('cde_admins', __g);

    select user_group_id from auth.user_group where tenant_id = __fgh and code = 'tenant_members' into __g;
    perform auth.set_user_group_as_hybrid('p18', 1, 'p18', __g, __fgh);
    perform auth.create_user_group_mapping('p18', 1, 'p18', __g, 'p18_aad', 'fgh', 'Azure FGH', _tenant_id := __fgh);
    perform auth.create_user_group_mapping('p18', 1, 'p18', __g, 'p18_aad', 'abc', 'Azure ABC', _tenant_id := __fgh);

    select user_group_id from auth.user_group where tenant_id = __fgh and code = 'tenant_admins' into __g;
    perform auth.set_user_group_as_hybrid('p18', 1, 'p18', __g, __fgh);
    perform auth.create_user_group_mapping('p18', 1, 'p18', __g, 'p18_aad', 'fghadmins', 'Azure FGHAdmins', _tenant_id := __fgh);
    insert into _p18 values ('fgh_admins', __g);

    raise notice 'PASS: setup (ABC=%, CDE=%, FGH=%)', __abc, __cde, __fgh;
end $$;

-- the app's login: identity + provider groups, as svc_authenticator
create or replace function pg_temp.p18_login(_name text, _groups text[], _provider text default 'p18_aad', _uid text default null, _oid text default null)
    returns table(__user_id bigint, __outcome_code text)
    language plpgsql
as
$$
declare
    __r record;
begin
    select * from auth.ensure_user_from_provider('p18', 3, 'p18', _provider
        , coalesce(_uid, 'uid-' || _name), coalesce(_oid, 'oid-' || _name)
        , _name || '@p18.com', initcap(_name), _name || '@p18.com') into __r;
    if __r.__user_id is not null and _provider = 'p18_aad' then
        perform auth.ensure_groups_and_permissions('p18', 3, 'p18', __r.__user_id, _provider, _groups, null);
    end if;
    return query select __r.__user_id, __r.__outcome_code;
end;
$$;

-- tenant codes in the user's combobox and where they are admin
create or replace function pg_temp.p18_tenants(_name text) returns text
    language sql
as
$$
    select coalesce((select string_agg(a.__tenant_code, ',' order by a.__tenant_code)
                     from auth.get_user_available_tenants(ui.user_id, 'p18', ui.user_id) a
                     where a.__tenant_code like 'p18\_%'), '-')
        || ' / admin: ' ||
           coalesce((select string_agg(t.code, ',' order by t.code) from auth.tenant t
                     where t.code like 'p18\_%'
                       and auth.has_permission(ui.user_id, 'p18', 'tenants.update_tenant', t.tenant_id, false)), '-')
    from auth.user_info ui
    where ui.username = _name || '@p18.com'
$$;

create or replace function pg_temp.p18_is(_what text, _actual text, _expected text) returns void
    language plpgsql
as
$$
begin
    if _actual is not distinct from _expected then
        raise notice 'PASS: %', _what;
    else
        raise notice 'FAIL: % - expected %, got %', _what, _expected, _actual;
    end if;
end;
$$;
