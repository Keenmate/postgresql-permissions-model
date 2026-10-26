set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 9: validate_api_key — future and no expiry validate, past expiry is refused
-- ============================================================================
do $$
declare
    __admin_id   bigint := (select val::bigint from _tss where key = 'admin_id');
    __api_key_id int;
    __api_key    text;
    __api_secret text;
    __user_id    bigint;
    __raised     text;
begin
    raise notice 'TEST 9: validate_api_key honours expire_at';

    select r.__api_key_id, r.__api_key, r.__api_secret
    from auth.create_api_key('tss_test', __admin_id, 'tss-9', 'TSS future key', null, null, null,
                             _expire_at := now() + interval '1 day', _tenant_id := 1) r
    into __api_key_id, __api_key, __api_secret;

    select v.__user_id
    from auth.validate_api_key('tss_test', __admin_id, 'tss-9', __api_key, __api_secret, _tenant_id := 1) v
    into __user_id;
    if __user_id is null then
        raise exception '  FAIL: key with future expiry did not validate';
    end if;

    -- move the expiry into the past
    perform auth.update_api_key('tss_test', __admin_id, 'tss-9', __api_key_id, 'TSS expired key', null,
                                now() - interval '1 minute', null, 1);

    begin
        perform auth.validate_api_key('tss_test', __admin_id, 'tss-9', __api_key, __api_secret, _tenant_id := 1);
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '30001' then
        raise exception '  FAIL: expired key: expected 30001, got %', coalesce(__raised, 'no error');
    end if;

    -- clear the expiry again
    perform auth.update_api_key('tss_test', __admin_id, 'tss-9', __api_key_id, 'TSS key', null, null, null, 1);

    select v.__user_id
    from auth.validate_api_key('tss_test', __admin_id, 'tss-9', __api_key, __api_secret, _tenant_id := 1) v
    into __user_id;
    if __user_id is null then
        raise exception '  FAIL: key without expiry did not validate';
    end if;

    raise notice '  PASS: future/none validate, past expiry refused with 30001';
end $$;
