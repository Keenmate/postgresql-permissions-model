set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Login never adds or removes members of synced groups; picker members are
-- not tenant members; users created by the sync claim their account
-- ============================================================================
do $$
begin
    raise notice '';
    raise notice '--- 003: login vs sync, membership ---';

    -- state from 002: ABC Azure users = alice; product owners = (none). Restage petr as owner.
    perform pg_temp.gs_stage('o3', array['petr']);
    perform auth.process_external_group_member_sync('gs', 6, 'gs');

    -- alice (created by the sync) logs in for the first time, token without the abc group
    perform pg_temp.gs_is('alice claims the user the sync created', pg_temp.gs_login('alice', array[]::text[]), 'user_logged_in');
    perform pg_temp.gs_is('login without the group keeps alice''s synced membership', pg_temp.gs_members('g'), 'alice');

    -- carol is in Azure ABC per her token but not synced yet
    perform pg_temp.gs_login('carol', array['abc']);
    perform pg_temp.gs_is('login with the group does not add carol to a synced group', pg_temp.gs_members('g'), 'alice');

    -- tenant membership: alice through a granting group; petr is only on a picker list
    perform pg_temp.gs_is('ABC members: alice only (picker list grants nothing)', pg_temp.gs_tenant_members(), 'alice');
    perform pg_temp.gs_is('petr is still a candidate owner', pg_temp.gs_members('po'), 'petr');
end $$;
