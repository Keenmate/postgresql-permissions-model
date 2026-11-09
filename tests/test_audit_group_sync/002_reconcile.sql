set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- The full sync runs, adds and removes; removal keeps the user
-- ============================================================================
do $$
declare
    __state text;
    __plain int;
begin
    raise notice '';
    raise notice '--- 002: reconcile ---';

    -- staged in 001: abc = alice, bob; product owners: o1 = petr, olga; o2 = petr; o3 = (empty)
    perform pg_temp.gs_stage('o1', array['petr', 'olga']);
    perform pg_temp.gs_stage('o2', array['petr']);

    perform auth.process_external_group_member_sync('gs', 6, 'gs');
    perform pg_temp.gs_is('full sync as svc_group_syncer adds ABC Azure users', pg_temp.gs_members('g'), 'alice,bob');
    perform pg_temp.gs_is('product owners = union of O1, O2, O3', pg_temp.gs_members('po'), 'olga,petr');
    perform pg_temp.gs_is('users created by the sync', (select count(*)::text from auth.user_info
        where username in ('alice@gs.com', 'bob@gs.com', 'petr@gs.com', 'olga@gs.com')), '4');

    -- bob leaves Azure ABC
    perform pg_temp.gs_stage('abc', array['alice']);
    perform auth.process_external_group_member_sync('gs', 6, 'gs');
    perform pg_temp.gs_is('bob removed from ABC Azure users', pg_temp.gs_members('g'), 'alice');
    perform pg_temp.gs_is('bob''s user row stays', (select count(*)::text from auth.user_info where username = 'bob@gs.com'), '1');

    -- petr leaves O1 but is still in O2: still a candidate; olga leaves O1: gone
    perform pg_temp.gs_stage('o1', array[]::text[]);
    perform auth.process_external_group_member_sync('gs', 6, 'gs');
    perform pg_temp.gs_is('petr still a candidate through O2, olga removed', pg_temp.gs_members('po'), 'petr');

    perform pg_temp.gs_stage('o2', array[]::text[]);
    perform auth.process_external_group_member_sync_by_mapping('gs', 6, 'gs', (select val::int from _gs where key = 'm_o2'));
    perform pg_temp.gs_is('per-mapping sync removes too', pg_temp.gs_members('po'), '-');

    -- a group that is not synced cannot be synced
    insert into auth.user_group (created_by, updated_by, tenant_id, title, code, is_assignable, is_active, is_external, is_system)
    values ('gs', 'gs', (select val from _gs where key = 'abc'), 'GS Plain', 'gs_plain', true, true, true, false)
    returning user_group_id into __plain;
    insert into auth.user_group_mapping (created_by, user_group_id, provider_code, mapped_object_id)
    values ('gs', __plain, 'gs_aad', 'plain');
    begin
        perform auth.process_external_group_member_sync_by_mapping('gs', 6, 'gs'
            , (select user_group_mapping_id from auth.user_group_mapping where user_group_id = __plain));
        raise notice 'FAIL: a group that is not synced was synced';
    exception when others then
        get stacked diagnostics __state = returned_sqlstate;
        perform pg_temp.gs_is('sync of a group that is not synced rejected (33025)', __state, '33025');
    end;
end $$;
