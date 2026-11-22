set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Scenario 7: the group sync adds and removes members
--   provider me_sync (group sync), synced group "ME Synced" in ABC (ME Reader)
--   the syncer is user 6 (groups.sync_members in tenant 1)
-- ============================================================================
do $$
declare
    __abc  int := pg_temp.me('abc')::int;
    __g    int;
    __m    int;
    __dana bigint;
begin
    raise notice 'TEST 9: the group sync';

    insert into auth.provider (created_by, updated_by, code, is_active, allows_group_mapping, allows_group_sync)
    values ('me', 'me', 'me_sync', true, true, true);

    select g.__user_group_id from unsecure.create_user_group('me', 1, 'me', 'ME Synced', _is_external := true, _tenant_id := __abc) g into __g;
    update auth.user_group set is_synced = true where user_group_id = __g;
    perform unsecure.assign_permission('me', 1, 'me', __g, null, 'me_reader', _tenant_id := __abc);
    insert into auth.user_group_mapping (created_by, user_group_id, provider_code, mapped_object_id)
    values ('me', __g, 'me_sync', 'grp-sync')
    returning user_group_mapping_id into __m;

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, can_login)
    values ('me', 'me', 'normal', 'dana@me.com', 'dana@me.com', 'Dana', 'dana@me.com', true)
    returning user_id into __dana;

    insert into stage.external_group_member (created_by, user_group_id, user_group_mapping_id, member_upn, member_display_name, member_email)
    values ('me', __g, __m, 'dana@me.com', 'Dana', 'dana@me.com');
    perform auth.process_external_group_member_sync_by_mapping('me', 6, 'me', __m);
    perform pg_temp.me_is('synced in: on_join', pg_temp.me_runs(__dana), 'me_join');

    delete from stage.external_group_member where user_group_mapping_id = __m;
    perform auth.process_external_group_member_sync_by_mapping('me', 6, 'me', __m);
    perform pg_temp.me_is('synced out: on_leave', pg_temp.me_runs(__dana), 'me_join,me_leave');
    perform pg_temp.me_is('out of the snapshot', pg_temp.me_state(__dana), 'none');
end $$;
