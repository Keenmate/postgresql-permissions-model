set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 10: get_tenant_groups returns code in __group_code and title in __group_title
-- ============================================================================
do $$
declare
    __admin_id    bigint := (select val::bigint from _tss where key = 'admin_id');
    __group_a_id  int    := (select val::int from _tss where key = 'group_a_id');
    __group_code  text;
    __group_title text;
begin
    raise notice 'TEST 10: get_tenant_groups columns';

    select g.__group_code, g.__group_title
    from auth.get_tenant_groups('tss_test', __admin_id, 'tss-10', 1) g
    where g.__user_group_id = __group_a_id
    into __group_code, __group_title;

    if __group_code is distinct from 'tss_group_a' or __group_title is distinct from 'TSS Group A' then
        raise exception '  FAIL: got code=% title=%', __group_code, __group_title;
    end if;

    raise notice '  PASS: code and title in the right columns';
end $$;

-- ============================================================================
-- TEST 11: *_as_system group helpers return their row; member helper stays in _tenant_id
-- ============================================================================
do $$
declare
    __tenant_b_id int := (select val::int from _tss where key = 'tenant_b_id');
    __group       auth.user_group;
    __member      auth.user_group_member;
begin
    raise notice 'TEST 11: create_user_group_as_system / create_user_group_member_as_system';

    -- same title in both tenants; the member helper must pick the one in _tenant_id
    select * from unsecure.create_user_group_as_system('TSS Shared Title', _tenant_id := 1) into __group;
    if __group.user_group_id is null then
        raise exception '  FAIL: create_user_group_as_system returned no row';
    end if;

    select * from unsecure.create_user_group_as_system('TSS Shared Title', _tenant_id := __tenant_b_id) into __group;
    if __group.user_group_id is null or __group.tenant_id <> __tenant_b_id then
        raise exception '  FAIL: create_user_group_as_system returned no row for tenant B';
    end if;

    select * from unsecure.create_user_group_member_as_system('tss_plain', 'TSS Shared Title', __tenant_b_id) into __member;
    if __member.member_id is null then
        raise exception '  FAIL: create_user_group_member_as_system returned no row';
    end if;
    if __member.user_group_id <> __group.user_group_id then
        raise exception '  FAIL: member added to group % instead of tenant B group %', __member.user_group_id, __group.user_group_id;
    end if;

    raise notice '  PASS: helpers return rows and resolve the group in _tenant_id';
end $$;
