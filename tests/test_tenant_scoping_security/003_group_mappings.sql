set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- TEST 7: create_user_group_mapping — foreign tenant (33011), inactive (33012),
--         duplicate (33023)
-- ============================================================================
do $$
declare
    __admin_id          bigint := (select val::bigint from _tss where key = 'admin_id');
    __group_a_id        int    := (select val::int from _tss where key = 'group_a_id');
    __group_inactive_id int    := (select val::int from _tss where key = 'group_inactive_id');
    __group_b_id        int    := (select val::int from _tss where key = 'group_b_id');
    __mapping_id        int;
    __raised            text;
begin
    raise notice 'TEST 7: create_user_group_mapping validation';

    begin
        perform auth.create_user_group_mapping('tss_test', __admin_id, 'tss-7', __group_b_id, 'tss_prov', 'tss-x');
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '33011' then
        raise exception '  FAIL: foreign-tenant group: expected 33011, got %', coalesce(__raised, 'no error');
    end if;

    __raised := null;
    begin
        perform auth.create_user_group_mapping('tss_test', __admin_id, 'tss-7', __group_inactive_id, 'tss_prov', 'tss-x');
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '33012' then
        raise exception '  FAIL: inactive group: expected 33012, got %', coalesce(__raised, 'no error');
    end if;

    select m.__user_group_mapping_id
    from auth.create_user_group_mapping('tss_test', __admin_id, 'tss-7', __group_a_id, 'tss_prov', 'TSS-A-Object') m
    into __mapping_id;
    if __mapping_id is null then
        raise exception '  FAIL: valid mapping was not created';
    end if;

    __raised := null;
    begin
        -- different case, same normalized key
        perform auth.create_user_group_mapping('tss_test', __admin_id, 'tss-7', __group_a_id, 'tss_prov', 'tss-a-object');
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '33023' then
        raise exception '  FAIL: duplicate mapping: expected 33023, got %', coalesce(__raised, 'no error');
    end if;

    insert into _tss values ('mapping_a_id', __mapping_id::text);
    raise notice '  PASS: foreign 33011, inactive 33012, duplicate 33023, valid mapping created';
end $$;

-- ============================================================================
-- TEST 8: delete_user_group_mapping — foreign tenant / unknown id (33022), own works
-- ============================================================================
do $$
declare
    __admin_id     bigint := (select val::bigint from _tss where key = 'admin_id');
    __mapping_a_id int    := (select val::int from _tss where key = 'mapping_a_id');
    __mapping_b_id int    := (select val::int from _tss where key = 'mapping_b_id');
    __raised       text;
begin
    raise notice 'TEST 8: delete_user_group_mapping scoping';

    begin
        perform auth.delete_user_group_mapping('tss_test', __admin_id, 'tss-8', __mapping_b_id, 1);
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '33022' then
        raise exception '  FAIL: foreign-tenant mapping: expected 33022, got %', coalesce(__raised, 'no error');
    end if;
    if not exists(select from auth.user_group_mapping where user_group_mapping_id = __mapping_b_id) then
        raise exception '  FAIL: foreign-tenant mapping was deleted';
    end if;

    __raised := null;
    begin
        perform auth.delete_user_group_mapping('tss_test', __admin_id, 'tss-8', -1, 1);
    exception when others then
        __raised := sqlstate;
    end;
    if __raised is distinct from '33022' then
        raise exception '  FAIL: unknown mapping: expected 33022, got %', coalesce(__raised, 'no error');
    end if;

    perform auth.delete_user_group_mapping('tss_test', __admin_id, 'tss-8', __mapping_a_id, 1);
    if exists(select from auth.user_group_mapping where user_group_mapping_id = __mapping_a_id) then
        raise exception '  FAIL: own mapping was not deleted';
    end if;

    raise notice '  PASS: foreign/unknown 33022, own mapping deleted';
end $$;
