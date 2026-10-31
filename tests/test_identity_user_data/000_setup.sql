set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   iud_prov : test provider
--   admin    : full_admin perm set, NOT user 1 (user 1 bypasses every check)
-- ============================================================================
do $$
declare
    __admin_id bigint;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Identity user data - Starting';
    raise notice '=================================================================';

    insert into auth.provider (created_by, updated_by, code, is_active, allows_group_mapping)
    values ('iud_test', 'iud_test', 'iud_prov', true, false);

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, can_login)
    values ('iud_test', 'iud_test', 'normal', 'iud_admin', 'iud_admin', 'IUD Admin', 'iud_admin@test.com', true)
    returning user_id into __admin_id;

    perform unsecure.assign_permission_as_system(null::integer, __admin_id, 'full_admin');

    create temp table if not exists _iud (key text primary key, val text);
    delete from _iud;
    insert into _iud values ('admin_id', __admin_id::text);

    raise notice 'SETUP: admin=%', __admin_id;
end $$;
