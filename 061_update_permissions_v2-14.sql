/*
 * PostgreSQL Permissions Model — update v2.14
 * ===========================================
 *
 * Inactive resource roles grant nothing (audit decision D-06, resource part).
 * unsecure.get_effective_resource_access joined the role's flags without
 * looking at const.resource_role.is_active, so a role that was switched off
 * kept granting its flags everywhere it was assigned. Assignments are kept;
 * switching the role back on restores them.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.14', 'Inactive resource roles grant nothing',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'get_effective_resource_access ignores assignments of inactive resource roles.');


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
                          inner join const.resource_role rr on rr.code = rra.role_code and rr.is_active
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


select *
from public.stop_version_update('2.14', _component := 'postgresql_permissionmodel');
