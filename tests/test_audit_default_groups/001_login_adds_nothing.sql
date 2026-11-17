set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- A user who signs in through any provider, or whose permissions are rebuilt,
-- is not pulled into tenant B's group.
-- ============================================================================
do $$
declare
    __b      int := (select val from _dg where key = 'b');
    __g      int := (select val from _dg where key = 'g');
    __r      record;
    __victim bigint;
    __other  bigint;
begin
    raise notice 'TEST 1: login adds no one to a group of another tenant';

    select * from auth.ensure_user_from_provider('dg', 3, 'dg', 'dg_aad', 'uid-victim', 'oid-victim'
        , 'dg_victim@abc.com', 'DG victim', 'dg_victim@abc.com') into __r;
    __victim := __r.__user_id;
    perform auth.ensure_groups_and_permissions('dg', 3, 'dg', __victim, 'dg_aad', array['abc'], null);

    if exists(select from auth.user_group_member where user_group_id = __g and user_id = __victim) then
        raise exception 'FAIL: the new user was added to "B Everyone"';
    end if;
    if exists(select from auth.tenant_memberships where tenant_id = __b and user_id = __victim) then
        raise exception 'FAIL: the new user is a member of tenant B';
    end if;
    if exists(select from auth.user_group_member where user_id = __victim) then
        raise exception 'FAIL: the new user is a member of % group(s), expected none'
            , (select count(*) from auth.user_group_member where user_id = __victim);
    end if;
    raise notice 'PASS: login added the user to no group';

    raise notice 'TEST 2: the permission rebuild adds no one either';

    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, email, can_login)
    values ('dg', 'dg', 'normal', 'dg_other', 'dg_other', 'DG other', 'dg_other@test.com', true)
    returning user_id into __other;

    perform unsecure.recalculate_user_groups('dg', __other, null);

    if exists(select from auth.user_group_member where user_id = __other) then
        raise exception 'FAIL: recalculate_user_groups added the user to %'
            , (select string_agg(ug.code, ', ') from auth.user_group_member m
               inner join auth.user_group ug on ug.user_group_id = m.user_group_id where m.user_id = __other);
    end if;
    if exists(select from auth.tenant_memberships where tenant_id = __b and user_id = __other) then
        raise exception 'FAIL: the user is a member of tenant B';
    end if;
    raise notice 'PASS: recalculate_user_groups added the user to no group';
end $$;
