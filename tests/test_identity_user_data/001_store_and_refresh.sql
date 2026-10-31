set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 1: first login stores _user_data on the new identity, get_user_identity returns it
-- ============================================================================
do $$
declare
    __admin_id bigint := (select val::bigint from _iud where key = 'admin_id');
    __login    record;
    __identity record;
    __data     jsonb := '{"department": "Sales", "employee_id": "E-100"}';
begin
    raise notice 'TEST 1: first login stores _user_data';

    select * into __login
    from auth.ensure_user_from_provider('iud_test', __admin_id, 'iud-1', 'iud_prov',
        'iud_uid_1', 'iud_oid_1', 'iud_user1', 'IUD User 1', 'iud_user1@test.com', __data);

    insert into _iud values ('user_id', __login.__user_id::text);

    select * into __identity
    from auth.get_user_identity(__admin_id, 'iud-1r', __login.__user_id, 'iud_prov');

    if __identity.__user_data = __data and __identity.__uid = 'iud_uid_1' and __identity.__user_id = __login.__user_id then
        raise notice '  PASS: identity user_data = %', __identity.__user_data;
    else
        raise exception '  FAIL: expected % for uid iud_uid_1, got % for uid %', __data, __identity.__user_data, __identity.__uid;
    end if;
end $$;

-- ============================================================================
-- TEST 2: a later login with null _user_data keeps the stored data
-- ============================================================================
do $$
declare
    __admin_id bigint := (select val::bigint from _iud where key = 'admin_id');
    __user_id  bigint := (select val::bigint from _iud where key = 'user_id');
    __identity record;
begin
    raise notice 'TEST 2: null _user_data keeps the stored data';

    perform auth.ensure_user_from_provider('iud_test', __admin_id, 'iud-2', 'iud_prov',
        'iud_uid_1', 'iud_oid_1', 'iud_user1', 'IUD User 1', 'iud_user1@test.com');

    select * into __identity
    from auth.get_user_identity(__admin_id, 'iud-2r', __user_id, 'iud_prov');

    if __identity.__user_data = '{"department": "Sales", "employee_id": "E-100"}'::jsonb then
        raise notice '  PASS: user_data unchanged';
    else
        raise exception '  FAIL: user_data changed to %', __identity.__user_data;
    end if;
end $$;

-- ============================================================================
-- TEST 3: a later login with new _user_data replaces it and journals 10031
-- ============================================================================
do $$
declare
    __admin_id bigint := (select val::bigint from _iud where key = 'admin_id');
    __user_id  bigint := (select val::bigint from _iud where key = 'user_id');
    __identity record;
    __data     jsonb := '{"department": "Support", "title": "Lead"}';
    __journal  record;
begin
    raise notice 'TEST 3: new _user_data replaces the snapshot';

    perform auth.ensure_user_from_provider('iud_test', __admin_id, 'iud-3', 'iud_prov',
        'iud_uid_1', 'iud_oid_1', 'iud_user1', 'IUD User 1', 'iud_user1@test.com', __data);

    select * into __identity
    from auth.get_user_identity(__admin_id, 'iud-3r', __user_id, 'iud_prov');

    if __identity.__user_data = __data then
        raise notice '  PASS: user_data replaced (employee_id gone): %', __identity.__user_data;
    else
        raise exception '  FAIL: expected %, got %', __data, __identity.__user_data;
    end if;

    select j.event_id, j.data_payload into __journal
    from public.journal j
    where j.correlation_id = 'iud-3' and j.event_id = 10031;

    if __journal.event_id = 10031
        and __journal.data_payload -> 'user_data_keys' @> '["department", "title"]'::jsonb
        and __journal.data_payload ->> 'provider_code' = 'iud_prov' then
        raise notice '  PASS: journal 10031 with keys %', __journal.data_payload -> 'user_data_keys';
    else
        raise exception '  FAIL: expected journal 10031 with user_data_keys, got %', __journal.data_payload;
    end if;
end $$;

-- ============================================================================
-- TEST 4: the same _user_data again writes no journal entry
-- ============================================================================
do $$
declare
    __admin_id bigint := (select val::bigint from _iud where key = 'admin_id');
    __count    int;
begin
    raise notice 'TEST 4: unchanged _user_data is not journaled';

    perform auth.ensure_user_from_provider('iud_test', __admin_id, 'iud-4', 'iud_prov',
        'iud_uid_1', 'iud_oid_1', 'iud_user1', 'IUD User 1', 'iud_user1@test.com',
        '{"title": "Lead", "department": "Support"}');

    select count(*) into __count
    from public.journal j
    where j.correlation_id = 'iud-4' and j.event_id = 10031;

    if __count = 0 then
        raise notice '  PASS: no identity_updated entry';
    else
        raise exception '  FAIL: expected 0 identity_updated entries, got %', __count;
    end if;
end $$;

-- ============================================================================
-- TEST 5: first login without _user_data leaves it null
-- ============================================================================
do $$
declare
    __admin_id bigint := (select val::bigint from _iud where key = 'admin_id');
    __login    record;
    __identity record;
begin
    raise notice 'TEST 5: first login without _user_data';

    select * into __login
    from auth.ensure_user_from_provider('iud_test', __admin_id, 'iud-5', 'iud_prov',
        'iud_uid_2', 'iud_oid_2', 'iud_user2', 'IUD User 2', 'iud_user2@test.com');

    select * into __identity
    from auth.get_user_identity(__admin_id, 'iud-5r', __login.__user_id, 'iud_prov');

    if __identity.__uid = 'iud_uid_2' and __identity.__user_data is null then
        raise notice '  PASS: user_data is null';
    else
        raise exception '  FAIL: expected null user_data for iud_uid_2, got % for uid %', __identity.__user_data, __identity.__uid;
    end if;
end $$;

-- ============================================================================
-- TEST 6: a non-object _user_data (array) is stored and does not break the login
-- ============================================================================
do $$
declare
    __admin_id bigint := (select val::bigint from _iud where key = 'admin_id');
    __user_id  bigint := (select val::bigint from _iud where key = 'user_id');
    __identity record;
begin
    raise notice 'TEST 6: array _user_data';

    perform auth.ensure_user_from_provider('iud_test', __admin_id, 'iud-6', 'iud_prov',
        'iud_uid_1', 'iud_oid_1', 'iud_user1', 'IUD User 1', 'iud_user1@test.com', '["a", "b"]');

    select * into __identity
    from auth.get_user_identity(__admin_id, 'iud-6r', __user_id, 'iud_prov');

    if __identity.__user_data = '["a", "b"]'::jsonb then
        raise notice '  PASS: array stored';
    else
        raise exception '  FAIL: expected ["a", "b"], got %', __identity.__user_data;
    end if;
end $$;
