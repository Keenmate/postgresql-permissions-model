set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Every read answers "who is in T" the same way.
-- ============================================================================
do $$
declare
    __t     int    := (select val from _d03 where key = 't');
    __admin bigint := (select val from _d03 where key = 'admin');
begin
    raise notice '';
    raise notice '--- 001: one membership rule for every read ---';

    perform pg_temp.d03_check('search_users',
        array(select s.__username from auth.search_users(__admin, 'd03', null, 1, 1000, __t) s));
    perform pg_temp.d03_check('get_tenant_users',
        array(select s.__username from auth.get_tenant_users('d03', __admin, 'd03', __t) s));
    perform pg_temp.d03_check('get_tenant_members',
        array(select ui.username from auth.get_tenant_members('d03', __admin, 'd03', __t) s
              inner join auth.user_info ui on ui.user_id = s.__user_id));
    perform pg_temp.d03_check('notify_tenant_users',
        array(select ui.username from auth.notify_tenant_users n
              inner join auth.user_info ui on ui.user_id = n.user_id
              where n.tenant_id = __t));

    if (select s.__user_groups from auth.get_tenant_users('d03', __admin, 'd03', __t) s
        where s.__username = 'd03_direct') = '{}'::text[] then
        raise notice 'PASS: get_tenant_users shows a member without groups with an empty group list';
    else
        raise notice 'FAIL: get_tenant_users group list of d03_direct is not empty';
    end if;

    if to_regclass('auth.tenant_user') is null then
        raise notice 'PASS: auth.tenant_user is gone';
    else
        raise notice 'FAIL: auth.tenant_user still exists';
    end if;
end $$;

-- Every user sees the tenants they belong to (self-call needs no permission).
do $$
declare
    __t    int := (select val from _d03 where key = 't');
    __u    int := (select val from _d03 where key = 'u');
    __r    record;
    __got  int[];
    __exp  int[];
begin
    for __r in select key, val from _d03
               where key in ('admin', 'member', 'direct', 'owner', 'res', 'role', 'denied', 'inactive', 'outsider', 'picker')
               order by key
    loop
        __got := array(select a.__tenant_id from auth.get_user_available_tenants(__r.val, 'd03', __r.val) a
                       where a.__tenant_id in (__t, __u) order by 1);
        __exp := case
                     when __r.key = 'outsider' then array[__u]
                     when __r.key in ('denied', 'inactive', 'picker') then '{}'::int[]
                     else array[__t]
                 end;
        if __got = __exp then
            raise notice 'PASS: available tenants of d03_% = %', __r.key, __exp;
        else
            raise notice 'FAIL: available tenants of d03_% - expected %, got %', __r.key, __exp, __got;
        end if;
    end loop;
end $$;
