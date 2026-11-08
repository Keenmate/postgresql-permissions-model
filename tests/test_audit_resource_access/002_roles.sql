set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- Resource roles (bundles of flags) follow the same rules as direct grants:
-- a role on a folder covers everything below it, group roles count, a deny
-- above takes away exactly the denied flag, an inactive role grants nothing.
-- Folder model on d14_fs (path based):
--   r1.folder_a : U has role d14_editor (read, write); G1 denies write on r1
--   r2.folder_a : U has role d14_editor, no deny
--   r3          : G2 has role d14_editor
--   r4          : U has role d14_old (read), which is switched off
-- ============================================================================
do $$
declare
    __t  int    := pg_temp.d14('t')::int;
    __u  bigint := pg_temp.d14('u')::bigint;
    __g1 int    := pg_temp.d14('g1')::int;
    __g2 int    := pg_temp.d14('g2')::int;
begin
    raise notice '';
    raise notice '--- 002: resource roles ---';

    insert into const.resource_type_flag (resource_type_code, access_flag_code) values ('d14_fs', 'write')
    on conflict do nothing;
    insert into const.resource_role (code, resource_type, is_active, source) values
        ('d14_editor', 'd14_fs', true,  'd14'),
        ('d14_old',    'd14_fs', false, 'd14');
    insert into const.resource_role_flag (resource_role_code, access_flag_code) values
        ('d14_editor', 'read'), ('d14_editor', 'write'), ('d14_old', 'read');

    insert into auth.resource_role_assignment (created_by, updated_by, tenant_id, resource_type, root_type, resource_id, resource_path, user_id, user_group_id, role_code) values
        ('d14', 'd14', __t, 'd14_fs', 'd14_fs', '{}', 'r1.folder_a', __u,  null, 'd14_editor'),
        ('d14', 'd14', __t, 'd14_fs', 'd14_fs', '{}', 'r2.folder_a', __u,  null, 'd14_editor'),
        ('d14', 'd14', __t, 'd14_fs', 'd14_fs', '{}', 'r3',          null, __g2, 'd14_editor'),
        ('d14', 'd14', __t, 'd14_fs', 'd14_fs', '{}', 'r4',          __u,  null, 'd14_old');

    insert into auth.resource_access (created_by, updated_by, tenant_id, resource_type, root_type, resource_id, resource_path, user_id, user_group_id, access_flag, is_deny) values
        ('d14', 'd14', __t, 'd14_fs', 'd14_fs', '{}', 'r1', null, __g1, 'write', true);
end $$;

do $$
declare
    __t   int    := pg_temp.d14('t')::int;
    __u   bigint := pg_temp.d14('u')::bigint;
    __e   record;
    __has boolean;
    __flt boolean;
    __flg boolean;
begin
    for __e in
        select *
        from (values
                  ('r2.folder_a.hroch', 'read',  true,  'role on the folder covers a file in it (read)'),
                  ('r2.folder_a.hroch', 'write', true,  'role on the folder covers a file in it (write)'),
                  ('r2.folder_a.sub.deep', 'write', true, 'role on the folder covers any depth'),
                  ('r2.folder_b.x',     'read',  false, 'role on folder_a does not cover folder_b'),
                  ('r1.folder_a.hroch', 'read',  true,  'group deny on write above keeps the role''s read'),
                  ('r1.folder_a.hroch', 'write', false, 'group deny on write above removes the role''s write'),
                  ('r3.any.file',       'write', true,  'a group''s role counts for its members'),
                  ('r4.file',           'read',  false, 'an inactive role grants nothing')
             ) as v(path, flag, expected, why)
    loop
        __has := auth.has_resource_access(__u, 'c', 'd14_fs', '{}', __e.flag, __t, false, __e.path);
        __flt := exists(select from auth.filter_accessible_resources(__u, 'c', 'd14_fs', null, __e.flag, __t, array[__e.path]));
        __flg := exists(select from auth.get_resource_access_flags(__u, 'c', 'd14_fs', null, __t, __e.path) f
                        where f.__access_flag = __e.flag);

        if __has is distinct from __e.expected then
            raise notice 'FAIL: % % - has_resource_access % (expected %): %', __e.path, __e.flag, __has, __e.expected, __e.why;
        else
            raise notice 'PASS: % % - %', __e.path, __e.flag, __e.why;
        end if;

        if __flt is distinct from __has or __flg is distinct from __has then
            raise notice 'FAIL: % % - bulk functions disagree: has %, filter %, flags %', __e.path, __e.flag, __has, __flt, __flg;
        else
            raise notice 'PASS: % % - filter and flags agree', __e.path, __e.flag;
        end if;
    end loop;

    -- the flags call names the role as the source
    if exists(select from auth.get_resource_access_flags(__u, 'c', 'd14_fs', null, __t, 'r2.folder_a.hroch') f
              where f.__access_flag = 'write' and f.__source = 'role:d14_editor') then
        raise notice 'PASS: flags report role:d14_editor as the source';
    else
        raise notice 'FAIL: flags do not report role:d14_editor as the source';
    end if;
end $$;
