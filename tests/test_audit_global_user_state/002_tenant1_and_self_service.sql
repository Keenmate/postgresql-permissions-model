set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- sysadmin holds the same permissions in tenant 1: every call works, also
-- when the app passes _tenant_id = B. The target changes its own password,
-- profile and identity link without any permission.
-- ============================================================================
do $$
begin
    raise notice '';
    raise notice '--- 002: permission in tenant 1 works for any _tenant_id; self-service is free ---';

    perform pg_temp.d04_expect('tenant 1: lock_user',    'select * from auth.lock_user(''t'', {sysadmin_id}, ''c'', {target_id}, null, {b_id})', null);
    perform pg_temp.d04_expect('tenant 1: unlock_user',  'select * from auth.unlock_user(''t'', {sysadmin_id}, ''c'', {target_id}, null, {b_id})', null);
    perform pg_temp.d04_expect('tenant 1: disable_user', 'select * from auth.disable_user(''t'', {sysadmin_id}, ''c'', {target_id}, null, {b_id})', null);
    perform pg_temp.d04_expect('tenant 1: enable_user',  'select * from auth.enable_user(''t'', {sysadmin_id}, ''c'', {target_id}, null, {b_id})', null);
    perform pg_temp.d04_expect('tenant 1: update_user_password',
        'select * from auth.update_user_password(''t'', {sysadmin_id}, ''c'', {target_id}, ''admin-hash'', null, null, {b_id})', null);
    perform pg_temp.d04_expect('tenant 1: disable_user_identity',
        'select * from auth.disable_user_identity(''t'', {sysadmin_id}, ''c'', {target_id}, ''email'', null, {b_id})', null);
    perform pg_temp.d04_expect('tenant 1: enable_user_identity',
        'select * from auth.enable_user_identity(''t'', {sysadmin_id}, ''c'', {target_id}, ''email'', null, {b_id})', null);
    perform pg_temp.d04_expect('tenant 1: update_user_data',
        'select * from auth.update_user_data(''t'', {sysadmin_id}, ''c'', {target_id}, ''Admin'', _tenant_id := {b_id})', null);
    perform pg_temp.d04_expect('tenant 1: enroll_mfa',
        'select * from auth.enroll_mfa(''t'', {sysadmin_id}, ''c'', {target_id}, ''totp'', ''secret'', null, {b_id})', null);
    perform pg_temp.d04_expect('tenant 1: confirm_mfa_enrollment',
        'select auth.confirm_mfa_enrollment(''t'', {sysadmin_id}, ''c'', {target_id}, ''totp'', true, null, {b_id})', null);
    perform pg_temp.d04_expect('tenant 1: reset_mfa',
        'select * from auth.reset_mfa(''t'', {sysadmin_id}, ''c'', {target_id}, ''totp'', null, {b_id})', null);
    perform pg_temp.d04_expect('tenant 1: create_blacklist_user',
        'select * from auth.create_blacklist_user(''t'', {sysadmin_id}, ''c'', ''auditd04_banned2'', _tenant_id := {b_id})', null);
    perform pg_temp.d04_expect('tenant 1: delete_blacklist_user',
        'select * from auth.delete_blacklist_user(''t'', {sysadmin_id}, ''c'', {blacklist_id}, {b_id})', null);

    perform pg_temp.d04_expect('self: update_user_password',
        'select * from auth.update_user_password(''t'', {target_id}, ''c'', {target_id}, ''own-hash'', null, null, {b_id})', null);
    perform pg_temp.d04_expect('self: update_user_data',
        'select * from auth.update_user_data(''t'', {target_id}, ''c'', {target_id}, ''Own'', _tenant_id := {b_id})', null);
    perform pg_temp.d04_expect('self: create_user_identity_link',
        'select * from auth.create_user_identity_link(''t'', {target_id}, ''c'', {target_id}, ''email'', ''auditd04_own@example.com'', _tenant_id := {b_id})', null);

    perform pg_temp.d04_expect('tenant 1: delete_user_info',
        'select * from auth.delete_user_info(''t'', {sysadmin_id}, ''c'', {target_id}, {b_id})', null);
end $$;

do $$
begin
    if not exists(select from auth.user_info where user_id = pg_temp.d04('target_id')::bigint) then
        raise notice 'PASS: target deleted by the tenant-1 admin';
    else
        raise notice 'FAIL: target still exists';
    end if;
end $$;
