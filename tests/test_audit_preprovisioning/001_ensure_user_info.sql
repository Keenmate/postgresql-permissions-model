set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- ensure_user_info is a service-account operation: users.register_user in tenant 1
-- ============================================================================
do $$
declare
    __nobody bigint;
    __state  text;
begin
    raise notice '';
    raise notice '--- 001: who may pre-provision ---';

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('p18', 'p18', 'normal', 'p18_nobody', 'p18_nobody', 'P18 Nobody', true)
    returning user_id into __nobody;

    begin
        perform auth.ensure_user_info('p18', __nobody, 'p18', 'zed@p18.com', 'Zed');
        raise notice 'FAIL: a user without permissions created a user';
    exception when others then
        get stacked diagnostics __state = returned_sqlstate;
        perform pg_temp.p18_is('ensure_user_info without users.register_user is rejected (32001)', __state, '32001');
    end;

    perform pg_temp.p18_is('nothing was created',
        (select count(*)::text from auth.user_info where username = 'zed@p18.com'), '0');

    perform pg_temp.p18_is('svc_registrator pre-provisions a user',
        (select u.__username from auth.ensure_user_info('p18', 2, 'p18', 'zed@p18.com', 'Zed') u), 'zed@p18.com');
end $$;
