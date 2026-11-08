set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Test 1: Auto-lockout sys_params exist with their defaults and are system rows
-- ============================================================================
DO $$
DECLARE
    __s record;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '-- Test 1: Verify sys_param values --';

    SELECT * INTO __s FROM unsecure.get_login_lockout_settings();

    IF __s.__max_failed_attempts = 5 AND __s.__window_minutes = 15 AND __s.__lockout_reset_hours = 24
        AND __s.__lockout_durations_minutes = array[15, 60, 240, 960, 1440] THEN
        RAISE NOTICE 'PASS: login_lockout sys_params correct (%)', row_to_json(__s);
    ELSE
        RAISE EXCEPTION 'FAIL: unexpected login_lockout settings %', row_to_json(__s);
    END IF;

    IF EXISTS(SELECT FROM const.sys_param WHERE group_code = 'login_lockout' AND NOT is_system)
        OR (SELECT count(*) FROM const.sys_param WHERE group_code = 'login_lockout') <> 4 THEN
        RAISE EXCEPTION 'FAIL: expected 4 login_lockout params, all is_system';
    END IF;
    RAISE NOTICE 'PASS: all 4 login_lockout params are system params';
END $$;
