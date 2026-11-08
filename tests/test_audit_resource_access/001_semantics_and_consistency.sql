set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Every candidate: has_resource_access gives the expected answer, and
-- filter_accessible_resources and get_resource_access_flags agree with it.
-- ============================================================================
do $$
declare
    __t    int    := pg_temp.d14('t')::int;
    __u    bigint := pg_temp.d14('u')::bigint;
    __e    record;
    __has  boolean;
    __flt  boolean;
    __flg  boolean;
begin
    raise notice '';
    raise notice '--- 001: semantics, single check vs bulk functions ---';

    for __e in select * from _d14_expect loop
        __has := auth.has_resource_access(__u, 'c', __e.resource_type, __e.resource_id, 'read', __t, false, __e.resource_path);

        if __e.resource_path is null then
            __flt := exists(select from auth.filter_accessible_resources(__u, 'c', __e.resource_type, array[__e.resource_id], 'read', __t) f
                            where f.__resource_id = __e.resource_id);
        else
            __flt := exists(select from auth.filter_accessible_resources(__u, 'c', __e.resource_type, null, 'read', __t, array[__e.resource_path]) f
                            where f.__resource_id = jsonb_build_object('path', __e.resource_path));
        end if;

        __flg := exists(select from auth.get_resource_access_flags(__u, 'c', __e.resource_type,
                            case when __e.resource_path is null then __e.resource_id end, __t, __e.resource_path) f
                        where f.__access_flag = 'read');

        if __has is distinct from __e.expected then
            raise notice 'FAIL: % % % - has_resource_access % (expected %): %',
                __e.resource_type, __e.resource_id, coalesce(__e.resource_path, ''), __has, __e.expected, __e.why;
        else
            raise notice 'PASS: % % % - %', __e.resource_type, __e.resource_id, coalesce(__e.resource_path, ''), __e.why;
        end if;

        if __flt is distinct from __has or __flg is distinct from __has then
            raise notice 'FAIL: % % % - bulk functions disagree: has %, filter %, flags %',
                __e.resource_type, __e.resource_id, coalesce(__e.resource_path, ''), __has, __flt, __flg;
        else
            raise notice 'PASS: % % % - filter and flags agree', __e.resource_type, __e.resource_id, coalesce(__e.resource_path, '');
        end if;
    end loop;
end $$;

-- ============================================================================
-- Matrix and the accessible-resources list follow the same rules
-- ============================================================================
do $$
declare
    __t     int    := pg_temp.d14('t')::int;
    __u     bigint := pg_temp.d14('u')::bigint;
    __ids   text;
begin
    -- project 5: read on the project and, inherited, on its docs
    if exists(select from auth.get_resource_access_matrix(__u, 'c', 'd14_proj', '{"proj":5}', __t) m
              where m.__resource_type = 'd14_proj.doc' and m.__access_flag = 'read') then
        raise notice 'PASS: matrix: project 5 grants read on its docs';
    else
        raise notice 'FAIL: matrix: project 5 does not show read on its docs';
    end if;

    -- project 4: group deny on the project - nothing readable
    if exists(select from auth.get_resource_access_matrix(__u, 'c', 'd14_proj', '{"proj":4}', __t) m
              where m.__access_flag = 'read') then
        raise notice 'FAIL: matrix: project 4 (group deny) still shows read';
    else
        raise notice 'PASS: matrix: project 4 (group deny) shows no read';
    end if;

    -- project 6: G1 deny on docs only - project read, docs not
    if exists(select from auth.get_resource_access_matrix(__u, 'c', 'd14_proj', '{"proj":6}', __t) m
              where m.__resource_type = 'd14_proj' and m.__access_flag = 'read')
       and not exists(select from auth.get_resource_access_matrix(__u, 'c', 'd14_proj', '{"proj":6}', __t) m
              where m.__resource_type = 'd14_proj.doc' and m.__access_flag = 'read') then
        raise notice 'PASS: matrix: project 6 readable, its docs not';
    else
        raise notice 'FAIL: matrix: project 6 wrong (project read, docs denied expected)';
    end if;

    select string_agg(r.__resource_id::text, ' ' order by r.__resource_id::text)
    from auth.get_user_accessible_resources(__u, 'c', __u, 'd14_proj.doc', 'read', __t) r
    into __ids;

    if __ids like '%"doc": 5%' or __ids like '%"doc": 2%' then
        raise notice 'FAIL: accessible list contains a doc denied at the project level: %', __ids;
    else
        raise notice 'PASS: accessible list leaves out docs denied at the project level';
    end if;

    if __ids like '%"proj": 2}%' and __ids like '%"proj": 5}%' then
        raise notice 'PASS: accessible list contains the partial key and the project grant';
    else
        raise notice 'FAIL: accessible list misses the partial key or the project grant: %', __ids;
    end if;
end $$;

-- ============================================================================
-- Groups can be denied through the API
-- ============================================================================
do $$
declare
    __t     int    := pg_temp.d14('t')::int;
    __u     bigint := pg_temp.d14('u')::bigint;
    __g2    int    := pg_temp.d14('g2')::int;
begin
    begin
        perform auth.deny_resource_access('t', 1, 'c', 'd14_proj', '{"proj":5}', null, array['read'], __t, null, __g2);
    exception when others then
        raise notice 'FAIL: deny_resource_access for a group raised: %', sqlerrm;
        return;
    end;

    if auth.has_resource_access(__u, 'c', 'd14_proj.doc', '{"proj":5,"doc":3}', 'read', __t, false) then
        raise notice 'FAIL: group deny on project 5 did not take away the user grant';
    else
        raise notice 'PASS: group deny on project 5 beats the user grant';
    end if;
end $$;
