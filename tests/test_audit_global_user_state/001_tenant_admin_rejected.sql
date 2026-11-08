set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- admin_b holds every users.* / mfa.* permission in tenant B only. Changing a
-- user's global state is rejected with 32001 and nothing changes.
-- ============================================================================
do $$
begin
    raise notice '';
    raise notice '--- 001: tenant B admin cannot change global user state ---';

    perform pg_temp.d04_expect('lock_user',    'select * from auth.lock_user(''t'', {admin_b_id}, ''c'', {target_id}, null, {b_id})', '32001');
    perform pg_temp.d04_expect('unlock_user',  'select * from auth.unlock_user(''t'', {admin_b_id}, ''c'', {target_id}, null, {b_id})', '32001');
    perform pg_temp.d04_expect('disable_user', 'select * from auth.disable_user(''t'', {admin_b_id}, ''c'', {target_id}, null, {b_id})', '32001');
    perform pg_temp.d04_expect('enable_user',  'select * from auth.enable_user(''t'', {admin_b_id}, ''c'', {target_id}, null, {b_id})', '32001');
    perform pg_temp.d04_expect('update_user_password',
        'select * from auth.update_user_password(''t'', {admin_b_id}, ''c'', {target_id}, ''new-hash'', null, null, {b_id})', '32001');
    perform pg_temp.d04_expect('disable_user_identity',
        'select * from auth.disable_user_identity(''t'', {admin_b_id}, ''c'', {target_id}, ''email'', null, {b_id})', '32001');
    perform pg_temp.d04_expect('enable_user_identity',
        'select * from auth.enable_user_identity(''t'', {admin_b_id}, ''c'', {target_id}, ''email'', null, {b_id})', '32001');
    perform pg_temp.d04_expect('verify_user_identity',
        'select auth.verify_user_identity(''t'', {admin_b_id}, ''c'', {target_id}, ''email'', null, {b_id})', '32001');
    perform pg_temp.d04_expect('create_user_identity_link',
        'select * from auth.create_user_identity_link(''t'', {admin_b_id}, ''c'', {target_id}, ''email'', ''auditd04_other@example.com'', _tenant_id := {b_id})', '32001');
    perform pg_temp.d04_expect('update_user_data',
        'select * from auth.update_user_data(''t'', {admin_b_id}, ''c'', {target_id}, ''Hijacked'', _tenant_id := {b_id})', '32001');
    perform pg_temp.d04_expect('update_user_preferences',
        'select * from auth.update_user_preferences(''t'', {admin_b_id}, ''c'', {target_id}, ''{"theme": "x"}'', {b_id})', '32001');
    perform pg_temp.d04_expect('enroll_mfa',
        'select * from auth.enroll_mfa(''t'', {admin_b_id}, ''c'', {target_id}, ''totp'', ''secret'', null, {b_id})', '32001');
    perform pg_temp.d04_expect('confirm_mfa_enrollment',
        'select auth.confirm_mfa_enrollment(''t'', {admin_b_id}, ''c'', {target_id}, ''totp'', true, null, {b_id})', '32001');
    perform pg_temp.d04_expect('disable_mfa',
        'select auth.disable_mfa(''t'', {admin_b_id}, ''c'', {target_id}, ''totp'', null, {b_id})', '32001');
    perform pg_temp.d04_expect('reset_mfa',
        'select * from auth.reset_mfa(''t'', {admin_b_id}, ''c'', {target_id}, ''totp'', null, {b_id})', '32001');
    perform pg_temp.d04_expect('create_blacklist_user',
        'select * from auth.create_blacklist_user(''t'', {admin_b_id}, ''c'', ''auditd04_banned2'', _tenant_id := {b_id})', '32001');
    perform pg_temp.d04_expect('delete_blacklist_user',
        'select * from auth.delete_blacklist_user(''t'', {admin_b_id}, ''c'', {blacklist_id}, {b_id})', '32001');
    perform pg_temp.d04_expect('delete_user_info',
        'select * from auth.delete_user_info(''t'', {admin_b_id}, ''c'', {target_id}, {b_id})', '32001');
end $$;

do $$
declare
    __u record;
begin
    select is_active, is_locked from auth.user_info where user_id = pg_temp.d04('target_id')::bigint into __u;
    if __u.is_active and not __u.is_locked then
        raise notice 'PASS: target is still active and unlocked';
    else
        raise notice 'FAIL: target state changed (active %, locked %)', __u.is_active, __u.is_locked;
    end if;

    if (select password_hash from auth.user_identity
        where user_id = pg_temp.d04('target_id')::bigint and provider_code = 'email') = 'hash' then
        raise notice 'PASS: target password unchanged';
    else
        raise notice 'FAIL: target password changed';
    end if;

    if exists(select from auth.user_mfa where user_id = pg_temp.d04('target_id')::bigint) then
        raise notice 'FAIL: an MFA enrollment was created for target';
    else
        raise notice 'PASS: no MFA enrollment for target';
    end if;

    if exists(select from auth.user_blacklist where blacklist_id = pg_temp.d04('blacklist_id')::bigint)
        and not exists(select from auth.user_blacklist where username = 'auditd04_banned2') then
        raise notice 'PASS: blacklist unchanged';
    else
        raise notice 'FAIL: blacklist changed';
    end if;
end $$;
