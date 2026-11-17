set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- The flag, its functions, its permission and its parameters/columns are gone.
-- ============================================================================
do $$
declare
    __left text;
begin
    raise notice 'TEST 3: user_group.is_default and active_user_groups.is_default are gone';
    select string_agg(table_name, ', ')
    from information_schema.columns
    where table_schema = 'auth' and table_name in ('user_group', 'active_user_groups') and column_name = 'is_default'
    into __left;
    if __left is not null then
        raise exception 'FAIL: is_default still exists on %', __left;
    end if;
    if not exists(select from information_schema.columns
                  where table_schema = 'auth' and table_name = 'tenant' and column_name = 'is_default') then
        raise exception 'FAIL: tenant.is_default (the default tenant) must stay';
    end if;
    raise notice 'PASS: the column is gone, tenant.is_default stays';

    raise notice 'TEST 4: assign_user_default_groups and users.add_to_default_groups are gone';
    select string_agg(n.nspname || '.' || p.proname, ', ')
    from pg_proc p inner join pg_namespace n on n.oid = p.pronamespace
    where p.proname = 'assign_user_default_groups'
    into __left;
    if __left is not null then
        raise exception 'FAIL: % still exist(s)', __left;
    end if;
    if exists(select from auth.permission where full_code = 'users.add_to_default_groups'::ext.ltree) then
        raise exception 'FAIL: permission users.add_to_default_groups still exists';
    end if;
    raise notice 'PASS: the functions and the permission are gone';

    raise notice 'TEST 5: no group function takes _is_default or returns __is_default';
    select string_agg(distinct n.nspname || '.' || p.proname, ', ')
    from pg_proc p inner join pg_namespace n on n.oid = p.pronamespace
    where n.nspname in ('auth', 'unsecure', 'internal', 'public')
      and p.proname like '%group%'
      and ('_is_default' = any (p.proargnames) or '__is_default' = any (p.proargnames))
    into __left;
    if __left is not null then
        raise exception 'FAIL: % still use(s) is_default', __left;
    end if;
    raise notice 'PASS: no _is_default / __is_default left';
end $$;

do $$
declare
    __b     int := (select val from _dg where key = 'b');
    __owner bigint := (select val from _dg where key = 'owner');
    __g     int;
    __r     record;
begin
    raise notice 'TEST 6: the group functions still work without the flag';

    select g.__user_group_id
    from auth.create_user_group('dg', __owner, 'dg', 'DG Plain', true, true, false, __b) g
    into __g;
    perform auth.update_user_group('dg', __owner, 'dg', __g, 'DG Plain 2', true, true, false, __b);

    select * from auth.get_user_group_by_id('dg', __owner, 'dg', __g, __b) into __r;
    if __r.__title is distinct from 'DG Plain 2' or __r.__tenant_id is distinct from __b then
        raise exception 'FAIL: get_user_group_by_id returned %', row_to_json(__r);
    end if;

    -- an old payload with is_default is accepted, the key is ignored
    select * from auth.ensure_user_groups('dg', __owner, 'dg'
        , '[{"title": "DG Ensured", "is_default": true}]'::jsonb, __b) into __r;
    if __r.__code is distinct from 'dg_ensured' or __r.__tenant_id is distinct from __b then
        raise exception 'FAIL: ensure_user_groups returned %', row_to_json(__r);
    end if;

    if (select count(*) from auth.search_user_groups(__owner, 'dg', '{"search_text": "DG "}'::jsonb, _tenant_id := __b)) <> 2 then
        raise exception 'FAIL: search_user_groups did not find both groups';
    end if;
    raise notice 'PASS: create / update / get / ensure / search work';
end $$;
