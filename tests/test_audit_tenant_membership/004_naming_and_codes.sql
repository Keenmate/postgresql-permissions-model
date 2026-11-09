set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- v2.17: the membership view is auth.tenant_memberships (the group keeps the
-- name tenant_members); tenant error codes 34004-34007 are registered.
-- ============================================================================
do $$
begin
    raise notice '';
    raise notice '--- 004: view name, error codes ---';

    if to_regclass('auth.tenant_memberships') is not null and to_regclass('auth.tenant_members') is null then
        raise notice 'PASS: membership view is auth.tenant_memberships';
    else
        raise notice 'FAIL: expected auth.tenant_memberships and no auth.tenant_members view';
    end if;

    if (select count(*) from const.event_code where event_id between 34004 and 34007) = 4
       and (select count(*) from const.event_message where event_id between 34004 and 34007 and language_code = 'en') = 4 then
        raise notice 'PASS: error codes 34004-34007 registered with messages';
    else
        raise notice 'FAIL: error codes 34004-34007 missing from const.event_code / event_message';
    end if;
end $$;
