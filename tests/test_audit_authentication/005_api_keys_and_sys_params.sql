set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 9: API-key validation outcomes; failures persist as apikey_validation_failed
-- ============================================================================
do $$
declare
    __admin_id bigint := (select val::bigint from _a02 where key = 'admin_id');
    __key      text;
    __secret   text;
    __tech_id  bigint;
    __r        record;
begin
    raise notice 'TEST 9: API key validation attempts';

    select k.__api_key, k.__api_secret
    from auth.create_api_key('audit02', __admin_id, 'audit02-t9', 'Audit02 key', null, null, null) k
    into __key, __secret;

    select * from auth.create_api_key_validation_attempt('audit02', __admin_id, 'audit02-t9', __key, 'wrong-secret') into __r;
    if __r.__event_id <> 30001 or __r.__user_id is not null then
        raise exception '  FAIL: wrong secret: %', row_to_json(__r);
    end if;
    if not exists(select from auth.user_event where user_event_id = __r.__user_event_id
                  and event_type_code = 'apikey_validation_failed' and event_data ->> 'reason' = 'wrong_secret') then
        raise exception '  FAIL: failed validation not persisted';
    end if;

    select * from auth.create_api_key_validation_attempt('audit02', __admin_id, 'audit02-t9', __key, __secret) into __r;
    if __r.__event_id <> 14010 or __r.__user_id is null then
        raise exception '  FAIL: valid key: %', row_to_json(__r);
    end if;
    __tech_id := __r.__user_id;

    update auth.user_info set is_active = false where user_id = __tech_id;
    select * from auth.create_api_key_validation_attempt('audit02', __admin_id, 'audit02-t9', __key, __secret) into __r;
    if __r.__event_id <> 33003 then
        raise exception '  FAIL: disabled technical user: %', row_to_json(__r);
    end if;
    update auth.user_info set is_active = true where user_id = __tech_id;

    update auth.api_key set expire_at = now() - interval '1 second' where api_key = __key;
    select * from auth.create_api_key_validation_attempt('audit02', __admin_id, 'audit02-t9', __key, __secret) into __r;
    if __r.__event_id <> 30006 or __r.__outcome_code <> 'err_api_key_expired' then
        raise exception '  FAIL: expired key: %', row_to_json(__r);
    end if;

    raise notice '  PASS: wrong secret 30001 persisted, valid 14010, disabled 33003, expired 30006';
end $$;

-- ============================================================================
-- TEST 10: system sys_params can be updated but not deleted; lockout values
--          are validated
-- ============================================================================
do $$
declare
    __raised text;
begin
    raise notice 'TEST 10: system sys_params';

    begin
        delete from const.sys_param where group_code = 'login_lockout' and code = 'lockout_durations_minutes';
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '31015' then
        raise exception '  FAIL: delete: expected 31015, got %', coalesce(__raised, 'no error');
    end if;

    __raised := null;
    begin
        update const.sys_param set is_system = false where group_code = 'login_lockout' and code = 'window_minutes';
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '31015' then
        raise exception '  FAIL: unset is_system: expected 31015, got %', coalesce(__raised, 'no error');
    end if;

    __raised := null;
    begin
        perform auth.update_sys_param(1, 'login_lockout', 'lockout_durations_minutes', '15,1h');
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '31016' then
        raise exception '  FAIL: invalid durations: expected 31016, got %', coalesce(__raised, 'no error');
    end if;

    __raised := null;
    begin
        perform auth.update_sys_param(1, 'login_lockout', 'max_failed_attempts', '0', 0);
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '31016' then
        raise exception '  FAIL: max_failed_attempts 0: expected 31016, got %', coalesce(__raised, 'no error');
    end if;

    perform auth.update_sys_param(1, 'login_lockout', 'max_failed_attempts', '7', 7);
    if (select number_value from const.sys_param where group_code = 'login_lockout' and code = 'max_failed_attempts') <> 7 then
        raise exception '  FAIL: valid update was not applied';
    end if;

    raise notice '  PASS: delete 31015, unset is_system 31015, invalid values 31016, valid update applied';
end $$;
