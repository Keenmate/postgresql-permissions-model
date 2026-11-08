/*
 * PostgreSQL Permissions Model — update v2.13
 * ===========================================
 *
 * Resource access semantics (audit decision D-14). One rule set, one
 * implementation:
 *
 *  - A stored row applies to a resource when the row's key is part of the
 *    resource's key (a partial key such as {"proj": 2} on the doc type covers
 *    every doc of project 2; lost in commit d71afdb) and, for path rows, the
 *    resource lies under the row's path. Rows on the resource's type and on
 *    every ancestor type count.
 *  - A deny wins. A deny for the user or for any group the user is in, at any
 *    ancestor level (type or path), beats every grant. Exceptions to a deny are
 *    not supported (a future exceptions table, if ever needed).
 *    Before: only the user's own deny counted, and only at the most specific
 *    type level that had any row, so a doc grant beat a project deny and group
 *    denies were never checked.
 *  - has_resource_access, filter_accessible_resources, get_resource_access_flags,
 *    get_resource_access_matrix and get_user_accessible_resources all evaluate
 *    through unsecure.get_effective_resource_access and give the same answer.
 *    Before: filter and flags compared keys in the wrong direction, so a
 *    project grant did not show its docs in lists although the single check
 *    allowed them.
 *  - deny_resource_access accepts _user_group_id (new last parameter); a group
 *    must belong to _tenant_id.
 *
 * Owners (active, of a live tenant) and user 1 keep seeing everything.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.13', 'Resource access: deny wins, partial keys, one evaluation',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'A user or group deny at any ancestor level beats every grant; partial keys cover descendants; all resource access functions evaluate through unsecure.get_effective_resource_access; deny_resource_access supports groups.');


/***
 *    ███████╗██╗   ██╗███╗   ██╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗███████╗
 *    ██╔════╝██║   ██║████╗  ██║██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║██╔════╝
 *    █████╗  ██║   ██║██╔██╗ ██║██║        ██║   ██║██║   ██║██╔██╗ ██║███████╗
 *    ██╔══╝  ██║   ██║██║╚██╗██║██║        ██║   ██║██║   ██║██║╚██╗██║╚════██║
 *    ██║     ╚██████╔╝██║ ╚████║╚██████╗   ██║   ██║╚██████╔╝██║  ██║███████║
 *    ╚═╝      ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
 *
 */

drop function if exists auth.deny_resource_access(text, bigint, text, text, jsonb, bigint, text[], integer, text);

-- The single evaluation of resource access. For every candidate (resource id,
-- optional path) of _resource_type it returns the flags the user holds and where
-- the first one comes from (direct > role:<code> > group title > group (role)).
-- A row applies when it is on _resource_type or an ancestor type, its key is part
-- of the candidate's key, and its path (if any) is an ancestor-or-self of the
-- candidate's path. Any applying deny (user or group) removes the flag.
-- Owners and user 1 are handled by the callers.
create or replace function unsecure.get_effective_resource_access(
    _user_id        bigint,
    _tenant_id      integer,
    _resource_type  text,
    _resource_ids   jsonb[],
    _resource_paths ext.ltree[] default null,
    _access_flag    text        default null
) returns table(__resource_id jsonb, __resource_path ext.ltree, __access_flag text, __source text)
    stable
    language plpgsql
as
$$
declare
    __group_ids      integer[];
    __root_type      text;
    __ancestor_types text[];
begin
    __group_ids := coalesce(unsecure.get_cached_group_ids(_user_id, _tenant_id), array []::integer[]);
    __root_type := split_part(_resource_type, '.', 1);

    select array_agg(rt.code)
    from const.resource_type rt
    where rt.path @> (select path from const.resource_type where code = _resource_type)
      and rt.is_active = true
    into __ancestor_types;

    return query
        with candidates as (
            select distinct coalesce(c.id, '{}'::jsonb) as id, c.path
            from unnest(_resource_ids, _resource_paths) as c(id, path)),
             applying as (
                 select c.id, c.path, ra.access_flag as flag, ra.is_deny
                      , ra.user_id, ra.user_group_id, null::text as role_code
                 from candidates c
                          inner join auth.resource_access ra
                                     on ra.root_type = __root_type
                                         and ra.tenant_id = _tenant_id
                                         and ra.resource_type = any (__ancestor_types)
                                         and c.id @> ra.resource_id
                                         and (ra.resource_path is null
                                             or (c.path is not null and c.path <@ ra.resource_path))
                                         and (ra.user_id = _user_id or ra.user_group_id = any (__group_ids))
                 where _access_flag is null
                    or ra.access_flag = _access_flag
                 union all
                 select c.id, c.path, rrf.access_flag_code, false
                      , rra.user_id, rra.user_group_id, rra.role_code
                 from candidates c
                          inner join auth.resource_role_assignment rra
                                     on rra.root_type = __root_type
                                         and rra.tenant_id = _tenant_id
                                         and rra.resource_type = any (__ancestor_types)
                                         and c.id @> rra.resource_id
                                         and (rra.resource_path is null
                                             or (c.path is not null and c.path <@ rra.resource_path))
                                         and (rra.user_id = _user_id or rra.user_group_id = any (__group_ids))
                          inner join const.resource_role_flag rrf on rrf.resource_role_code = rra.role_code
                 where _access_flag is null
                    or rrf.access_flag_code = _access_flag)
        select distinct on (a.id, a.path, a.flag)
               a.id
             , a.path
             , a.flag
             , case
                   when a.user_id is not null and a.role_code is null then 'direct'
                   when a.user_id is not null then 'role:' || a.role_code
                   when a.role_code is null then ug.title
                   else ug.title || ' (role:' || a.role_code || ')'
            end
        from applying a
                 left join auth.user_group ug on ug.user_group_id = a.user_group_id
        where not a.is_deny
          and not exists(select
                         from applying d
                         where d.is_deny
                           and d.id = a.id
                           and d.path is not distinct from a.path
                           and d.flag = a.flag)
        order by a.id, a.path, a.flag
               , case
                     when a.user_id is not null and a.role_code is null then 1
                     when a.user_id is not null then 2
                     when a.role_code is null then 3
                     else 4
            end
               , ug.title;
end;
$$;

create or replace function auth.has_resource_access(
    _user_id        bigint,
    _correlation_id text,
    _resource_type  text,
    _resource_id    jsonb   default '{}'::jsonb,
    _required_flag  text    default 'read',
    _tenant_id      integer default 1,
    _throw_err      boolean default true,
    _resource_path  text    default null
) returns boolean
    language plpgsql
as
$$
begin
    perform unsecure.validate_resource_identifier(_resource_id, _resource_path);

    if _user_id = 1 then
        return true;
    end if;

    if unsecure.is_active_tenant_owner(_user_id, _tenant_id) then
        return true;
    end if;

    if exists(select
              from unsecure.get_effective_resource_access(_user_id, _tenant_id, _resource_type
                  , array [coalesce(_resource_id, '{}'::jsonb)], array [ext.text2ltree(_resource_path)]
                  , _required_flag)) then
        return true;
    end if;

    if _throw_err then
        perform error.raise_35001(_user_id, _resource_type, _resource_id, _tenant_id);
    end if;

    return false;
end;
$$;

create or replace function auth.filter_accessible_resources(
    _user_id         bigint,
    _correlation_id  text,
    _resource_type   text,
    _resource_ids    jsonb[] default null,
    _required_flag   text    default 'read',
    _tenant_id       integer default 1,
    _resource_paths  text[]  default null
) returns table(__resource_id jsonb)
    language plpgsql
as
$$
begin
    if _resource_ids is null and _resource_paths is null then
        return;
    end if;

    if _user_id = 1 or unsecure.is_active_tenant_owner(_user_id, _tenant_id) then
        if _resource_ids is not null then
            return query select unnest(_resource_ids);
        end if;
        if _resource_paths is not null then
            return query select jsonb_build_object('path', p) from unnest(_resource_paths) as p;
        end if;
        return;
    end if;

    -- ID-based candidates
    if _resource_ids is not null then
        return query
            select e.__resource_id
            from unsecure.get_effective_resource_access(_user_id, _tenant_id, _resource_type
                     , _resource_ids, null, _required_flag) e;
    end if;

    -- Path-based candidates
    if _resource_paths is not null then
        return query
            select jsonb_build_object('path', e.__resource_path::text)
            from unsecure.get_effective_resource_access(_user_id, _tenant_id, _resource_type
                     , array_fill('{}'::jsonb, array [cardinality(_resource_paths)])
                     , (select array_agg(ext.text2ltree(p) order by o) from unnest(_resource_paths) with ordinality as x(p, o))
                     , _required_flag) e;
    end if;
end;
$$;

create or replace function auth.get_resource_access_flags(
    _user_id        bigint,
    _correlation_id text,
    _resource_type  text,
    _resource_id    jsonb   default '{}'::jsonb,
    _tenant_id      integer default 1,
    _resource_path  text    default null
) returns table(__access_flag text, __source text)
    language plpgsql
as
$$
begin
    perform unsecure.validate_resource_identifier(_resource_id, _resource_path);

    if _user_id = 1 then
        return query
            select raf.code, 'system'::text
            from const.resource_access_flag raf;
        return;
    end if;

    if unsecure.is_active_tenant_owner(_user_id, _tenant_id) then
        return query
            select raf.code, 'owner'::text
            from const.resource_access_flag raf;
        return;
    end if;

    return query
        select e.__access_flag, e.__source
        from unsecure.get_effective_resource_access(_user_id, _tenant_id, _resource_type
                 , array [coalesce(_resource_id, '{}'::jsonb)], array [ext.text2ltree(_resource_path)]) e;
end;
$$;

create or replace function auth.get_resource_access_matrix(
    _user_id        bigint,
    _correlation_id text,
    _resource_type  text,
    _resource_id    jsonb   default '{}'::jsonb,
    _tenant_id      integer default 1,
    _resource_path  text    default null
) returns table(
    __resource_type text,
    __access_flag   text,
    __source        text
)
    language plpgsql
as
$$
begin
    perform unsecure.validate_resource_identifier(_resource_id, _resource_path);

    -- System user and tenant owner get all valid flags on all descendant types
    if _user_id = 1 or unsecure.is_active_tenant_owner(_user_id, _tenant_id) then
        return query
            select rt.code, raf.code, case when _user_id = 1 then 'system' else 'owner' end::text
            from const.resource_type rt
            cross join const.resource_access_flag raf
            where rt.path <@ (select path from const.resource_type where code = _resource_type)
              and rt.is_active = true
              and (not exists (select 1 from const.resource_type_flag rtf where rtf.resource_type_code = rt.code)
                   or exists (select 1 from const.resource_type_flag rtf where rtf.resource_type_code = rt.code and rtf.access_flag_code = raf.code));
        return;
    end if;

    -- For the resource itself and every descendant type: the flags the user holds on
    -- "any <type> under this resource", evaluated by the same rules as a single check
    return query
        select rt.code, e.__access_flag, e.__source
        from const.resource_type rt
                 cross join lateral unsecure.get_effective_resource_access(_user_id, _tenant_id, rt.code
                     , array [coalesce(_resource_id, '{}'::jsonb)], array [ext.text2ltree(_resource_path)]) e
        where rt.path <@ (select path from const.resource_type where code = _resource_type)
          and rt.is_active = true;
end;
$$;

create or replace function auth.get_user_accessible_resources(
    _user_id         bigint,
    _correlation_id  text,
    _target_user_id  bigint,
    _resource_type   text,
    _access_flag     text    default 'read',
    _tenant_id       integer default 1
) returns table(
    __resource_id   jsonb,
    __resource_path text,
    __access_flags  text[],
    __source        text
)
    language plpgsql
as
$$
declare
    __group_ids      integer[];
    __root_type      text;
    __ancestor_types text[];
    __ids            jsonb[];
    __paths          ext.ltree[];
begin
    if _user_id <> _target_user_id then
        perform auth.has_permission(_user_id, _correlation_id, 'resources.get_grants', _tenant_id);
    end if;

    __group_ids := coalesce(unsecure.get_cached_group_ids(_target_user_id, _tenant_id), array []::integer[]);
    __root_type := split_part(_resource_type, '.', 1);

    select array_agg(rt.code)
    from const.resource_type rt
    where rt.path @> (select path from const.resource_type where code = _resource_type)
      and rt.is_active = true
    into __ancestor_types;

    -- Candidates: every resource the user or their groups hold a grant on (directly
    -- or through a role); each is then evaluated by the common rules, so denies
    -- anywhere above it remove it.
    select array_agg(g.resource_id), array_agg(g.resource_path)
    from (select distinct ra.resource_id, ra.resource_path
          from auth.resource_access ra
          where ra.root_type = __root_type
            and ra.tenant_id = _tenant_id
            and ra.resource_type = any (__ancestor_types)
            and not ra.is_deny
            and (ra.user_id = _target_user_id or ra.user_group_id = any (__group_ids))
          union
          select distinct rra.resource_id, rra.resource_path
          from auth.resource_role_assignment rra
          where rra.root_type = __root_type
            and rra.tenant_id = _tenant_id
            and rra.resource_type = any (__ancestor_types)
            and (rra.user_id = _target_user_id or rra.user_group_id = any (__group_ids))) g
    into __ids, __paths;

    if __ids is null then
        return;
    end if;

    return query
        select e.__resource_id
             , e.__resource_path::text
             , array_agg(e.__access_flag order by e.__access_flag)
             , string_agg(distinct e.__source, ', ')
        from unsecure.get_effective_resource_access(_target_user_id, _tenant_id, _resource_type
                 , __ids, __paths, _access_flag) e
        group by e.__resource_id, e.__resource_path;
end;
$$;

-- Deny for a user or (new) a group. Exactly one of _target_user_id / _user_group_id.
create or replace function auth.deny_resource_access(
    _created_by     text,
    _user_id        bigint,
    _correlation_id text,
    _resource_type  text,
    _resource_id    jsonb   default '{}'::jsonb,
    _target_user_id bigint  default null,
    _access_flags   text[]  default array['read'],
    _tenant_id      integer default 1,
    _resource_path  text    default null,
    _user_group_id  integer default null
) returns table(__resource_access_id bigint, __access_flag text)
    language plpgsql
as
$$
declare
    __flag             text;
    __last_id          bigint;
    __target_name      text;
    __root_type        text;
    __resource_path_lt ext.ltree;
begin
    perform auth.has_permission(_user_id, _correlation_id, 'resources.deny_access', _tenant_id);

    if (_target_user_id is null) = (_user_group_id is null) then
        raise exception 'Deny requires exactly one of _target_user_id and _user_group_id'
            using errcode = '35002';
    end if;

    if _user_group_id is not null then
        perform unsecure.validate_user_group_in_tenant(_user_group_id, _tenant_id);
    end if;

    perform unsecure.validate_resource_identifier(_resource_id, _resource_path);

    perform unsecure.validate_resource_type(_resource_type);
    perform unsecure.validate_access_flags(_access_flags);
    perform unsecure.validate_access_flags_for_type(_resource_type, _access_flags);
    perform unsecure.validate_resource_id(_resource_type, _resource_id);

    _resource_id      := coalesce(_resource_id, '{}'::jsonb);
    __root_type        := split_part(_resource_type, '.', 1);
    __resource_path_lt := ext.text2ltree(_resource_path);

    if _target_user_id is not null then
        select coalesce(display_name, code, user_id::text)
        from auth.user_info where user_id = _target_user_id
        into __target_name;
    else
        select title
        from auth.user_group where user_group_id = _user_group_id
        into __target_name;
    end if;

    foreach __flag in array _access_flags
    loop
        __last_id := null;

        select ra.resource_access_id from auth.resource_access ra
        where ra.root_type = __root_type
          and ra.resource_type = _resource_type
          and ra.tenant_id = _tenant_id
          and ra.resource_id = _resource_id
          and ra.resource_path is not distinct from __resource_path_lt
          and ra.user_id is not distinct from _target_user_id
          and ra.user_group_id is not distinct from _user_group_id
          and ra.access_flag = __flag
        into __last_id;

        if __last_id is not null then
            update auth.resource_access
            set is_deny = true,
                updated_by = _created_by,
                updated_at = now(),
                granted_by = _user_id
            where resource_access_id = __last_id
              and root_type = __root_type;
        else
            insert into auth.resource_access (
                created_by, updated_by, tenant_id, resource_type, root_type,
                resource_id, resource_path,
                user_id, user_group_id, access_flag, is_deny, granted_by
            ) values (
                _created_by, _created_by, _tenant_id, _resource_type, __root_type,
                _resource_id, __resource_path_lt,
                _target_user_id, _user_group_id, __flag, true, _user_id
            )
            returning resource_access_id into __last_id;
        end if;

        return query select __last_id, __flag;
    end loop;

    perform public.create_journal_message_for_entity(_created_by, _user_id, _correlation_id
        , 18012  -- resource_access_denied
        , 'resource_access', 0
        , jsonb_build_object('resource_type', _resource_type, 'resource_id', _resource_id,
            'resource_path', coalesce(_resource_path, ''),
            'target_type', case when _target_user_id is not null then 'user' else 'group' end,
            'target_name', __target_name,
            'access_flags', _access_flags)
        , _tenant_id);
end;
$$;


select *
from public.stop_version_update('2.13', _component := 'postgresql_permissionmodel');
