set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 5: tenant_admin (the template in tenant 1 and every copy) holds no
--         lifecycle or cross-tenant tenants.* permissions, and the effective
--         permissions of B's admin match.
-- ============================================================================
do $$
declare
    __b_id       int    := (select val::int from _a05 where key = 'b_id');
    __admin_b_id bigint := (select val::bigint from _a05 where key = 'admin_b_id');
    __bad        text;
    __code       text;
begin
    raise notice 'TEST 5: tenant_admin perm set contents';

    -- perm_set_perm stores nodes; a stored node grants its whole subtree
    select string_agg(distinct ps.tenant_id || ':' || p.full_code::text, ', ')
    from auth.perm_set ps
             inner join auth.perm_set_perm psp on psp.perm_set_id = ps.perm_set_id
             inner join auth.permission p on p.permission_id = psp.permission_id
             inner join auth.permission forbidden
                        on forbidden.node_path <@ p.node_path
                            and forbidden.full_code::text in ('tenants.create_tenant', 'tenants.purge_tenant',
                                                              'tenants.get_all_tenants', 'tenants.read_all_tenants',
                                                              'tenants.get_all_users', 'tenants.get_all_groups')
    where ps.code = 'tenant_admin'
    into __bad;
    if __bad is not null then
        raise exception '  FAIL: tenant_admin grants lifecycle/cross-tenant permissions via: %', __bad;
    end if;

    foreach __code in array array['tenants.update_tenant', 'tenants.delete_tenant', 'tenants.get_users'] loop
        if not auth.has_permission(__admin_b_id, 'audit05-t5', __code, __b_id, false) then
            raise exception '  FAIL: admin of B lost %', __code;
        end if;
    end loop;

    foreach __code in array array['tenants.purge_tenant', 'tenants.create_tenant', 'tenants.get_all_tenants'] loop
        if auth.has_permission(__admin_b_id, 'audit05-t5', __code, __b_id, false) then
            raise exception '  FAIL: admin of B still has %', __code;
        end if;
    end loop;

    raise notice '  PASS: no lifecycle/cross-tenant permissions in any tenant_admin set';
end $$;
