set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Reads with their own scoping rules
--   get_invitations from tenant 1 with _target_tenant_id needs get_all_invitations
--   in tenant 1, not in the target tenant.
--   get_api_key_permissions checks api_keys.search in _tenant_id itself and
--   only shows keys of _tenant_id.
-- ============================================================================
do $$
begin
    raise notice '';
    raise notice '--- 004: get_invitations and get_api_key_permissions scoping ---';

    -- admin_b holds invitations.get_all_invitations in B, not in tenant 1
    perform pg_temp.a02_expect('get_invitations from tenant 1 with permission only in the target tenant',
        'select * from auth.get_invitations(''t'', {admin_b_id}, ''c'', 1, {b_id})', '32001');

    perform pg_temp.a02_expect('get_api_key_permissions of A''s key from B',
        'select * from auth.get_api_key_permissions({admin_b_id}, ''c'', {key_a_id}, {b_id})', '30007');
end $$;

do $$
declare
    __b     int    := pg_temp.a02('b_id')::int;
    __key_b int    := pg_temp.a02('key_b_id')::int;
    __admin bigint := pg_temp.a02('admin_b_id')::bigint;
    __codes text;
begin
    perform auth.assign_api_key_permissions('t', __admin, 'c', __key_b, null, array['api_keys.search'], __b);

    begin
        select string_agg(p.__permission_full_code, ',')
        from auth.get_api_key_permissions(__admin, 'c', __key_b, __b) p
        into __codes;
    exception when others then
        raise notice 'FAIL: own tenant: get_api_key_permissions raised %', sqlerrm;
        return;
    end;

    if __codes = 'api_keys.search' then
        raise notice 'PASS: own tenant: get_api_key_permissions returns the key''s permission';
    else
        raise notice 'FAIL: own tenant: get_api_key_permissions returned %', coalesce(__codes, '<nothing>');
    end if;
end $$;
