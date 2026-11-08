set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- Since v2.6 ensure_user_from_provider returns failures as outcomes (user columns
-- null) instead of raising, so the user_login_failed event persists.

-- ============================================================================
-- TESTS 17-19 (+ locked): user disabled, login disabled, identity disabled,
--   user locked (provider logins of locked users were allowed before v2.6)
-- ============================================================================
DO $$
DECLARE
    __aad_user_id bigint := current_setting('test.aad_user_id')::bigint;
    __case record;
    __r record;
BEGIN
    RAISE NOTICE 'TESTS 17-19: ensure_user_from_provider failure outcomes';

    FOR __case IN
        SELECT * FROM (VALUES
            ('17', 'update auth.user_info set is_active = false where user_id = %s', 'update auth.user_info set is_active = true where user_id = %s', 33003, 'user_disabled'),
            ('18', 'update auth.user_info set can_login = false where user_id = %s', 'update auth.user_info set can_login = true where user_id = %s', 33005, 'login_disabled'),
            ('19', 'update auth.user_identity set is_active = false where provider_code = ''aad'' and user_id = %s', 'update auth.user_identity set is_active = true where provider_code = ''aad'' and user_id = %s', 33008, 'identity_disabled'),
            ('19b', 'update auth.user_info set is_locked = true where user_id = %s', 'update auth.user_info set is_locked = false where user_id = %s', 33004, 'user_locked')
        ) v(test_no, break_sql, fix_sql, expected_event_id, expected_reason)
    LOOP
        EXECUTE format(__case.break_sql, __aad_user_id);

        SELECT * INTO __r
        FROM auth.ensure_user_from_provider('reg_test', 1, 'fail-provider-' || __case.test_no, 'aad', 'regtest_aad_uid_1', 'regtest_aad_oid_1',
            'regtest_aad_user', 'RegTest AAD User', 'regtest_aad@test.com');

        IF __r.__event_id IS DISTINCT FROM __case.expected_event_id OR __r.__user_id IS NOT NULL
            OR NOT EXISTS(SELECT FROM auth.user_event WHERE user_event_id = __r.__user_event_id
                          AND event_type_code = 'user_login_failed' AND event_data->>'reason' = __case.expected_reason) THEN
            RAISE EXCEPTION '  FAIL: TEST %: expected % (%), got %', __case.test_no, __case.expected_event_id, __case.expected_reason, row_to_json(__r);
        END IF;

        RAISE NOTICE '  PASS: TEST %: outcome %, no user returned, % event persisted', __case.test_no, __r.__event_id, __case.expected_reason;

        EXECUTE format(__case.fix_sql, __aad_user_id);
    END LOOP;
END $$;
