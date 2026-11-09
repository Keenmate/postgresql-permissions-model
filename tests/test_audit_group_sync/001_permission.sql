set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Sync needs groups.sync_members in tenant 1
-- ============================================================================
do $$
declare
    __nobody bigint;
    __state  text;
begin
    raise notice '';
    raise notice '--- 001: who may sync ---';

    perform pg_temp.gs_stage('abc', array['alice', 'bob']);

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('gs', 'gs', 'normal', 'gs_nobody', 'gs_nobody', 'GS Nobody', true)
    returning user_id into __nobody;

    begin
        perform auth.process_external_group_member_sync_by_mapping('gs', __nobody, 'gs', (select val::int from _gs where key = 'm_abc'));
        raise notice 'FAIL: a user without permissions ran the sync by mapping';
    exception when others then
        get stacked diagnostics __state = returned_sqlstate;
        perform pg_temp.gs_is('sync by mapping without groups.sync_members rejected (32001)', __state, '32001');
    end;

    begin
        perform auth.process_external_group_member_sync('gs', __nobody, 'gs');
        raise notice 'FAIL: a user without permissions ran the full sync';
    exception when others then
        get stacked diagnostics __state = returned_sqlstate;
        perform pg_temp.gs_is('full sync without groups.sync_members rejected (32001)', __state, '32001');
    end;

    perform pg_temp.gs_is('nothing synced, no users created', pg_temp.gs_members('g') || '/'
        || (select count(*)::text from auth.user_info where username in ('alice@gs.com', 'bob@gs.com')), '-/0');
end $$;
