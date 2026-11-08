set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- SETUP
--   types   d14_proj {proj} > d14_proj.doc {proj, doc}; d14_fs (path based)
--   tenant  T; user U (plain); groups G1, G2 (U is in both)
--   rows    one scenario per project number, see _d14_expect
-- ============================================================================
do $$
declare
    __t  int;
    __u  bigint;
    __g1 int;
    __g2 int;
begin
    raise notice '';
    raise notice '=================================================================';
    raise notice 'Audit D-14: resource access semantics - Starting';
    raise notice '=================================================================';

    insert into const.resource_type (code, source, path, key_schema) values
        ('d14_proj',     'd14', 'd14_proj',     '{"proj": "int"}'),
        ('d14_proj.doc', 'd14', 'd14_proj.doc', '{"proj": "int", "doc": "int"}'),
        ('d14_fs',       'd14', 'd14_fs',       '{}');
    insert into const.resource_type_flag (resource_type_code, access_flag_code) values
        ('d14_proj', 'read'), ('d14_proj', 'write'), ('d14_proj.doc', 'read'), ('d14_proj.doc', 'write'),
        ('d14_fs', 'read');
    perform unsecure.ensure_resource_access_partition('d14_proj');
    perform unsecure.ensure_resource_access_partition('d14_fs');

    select t.__tenant_id from auth.create_tenant('d14', 1, 'd14', 'D14 tenant', 'd14_t') t into __t;
    insert into auth.user_info (created_by, updated_by, user_type_code, username, original_username, display_name, can_login)
    values ('d14', 'd14', 'normal', 'd14_u', 'd14_u', 'D14 user', true) returning user_id into __u;
    insert into auth.user_group (created_by, updated_by, tenant_id, title, code, is_assignable, is_active, is_external, is_system)
    values ('d14', 'd14', __t, 'D14 G1', 'd14_g1', true, true, false, false) returning user_group_id into __g1;
    insert into auth.user_group (created_by, updated_by, tenant_id, title, code, is_assignable, is_active, is_external, is_system)
    values ('d14', 'd14', __t, 'D14 G2', 'd14_g2', true, true, false, false) returning user_group_id into __g2;
    insert into auth.user_group_member (created_by, user_group_id, user_id, member_type_code)
    values ('d14', __g1, __u, 'manual'), ('d14', __g2, __u, 'manual');

    insert into auth.resource_access (created_by, updated_by, tenant_id, resource_type, root_type, resource_id, resource_path, user_id, user_group_id, access_flag, is_deny) values
    -- proj 1: user DENY on the project, user GRANT on doc 5
        ('d14', 'd14', __t, 'd14_proj',     'd14_proj', '{"proj":1}',         null, __u,  null, 'read', true),
        ('d14', 'd14', __t, 'd14_proj.doc', 'd14_proj', '{"proj":1,"doc":5}', null, __u,  null, 'read', false),
    -- proj 2: partial key - GRANT on the doc type with only {"proj":2} = every doc of project 2
        ('d14', 'd14', __t, 'd14_proj.doc', 'd14_proj', '{"proj":2}',         null, __u,  null, 'read', false),
    -- proj 3: group GRANT on the project, user DENY on doc 1
        ('d14', 'd14', __t, 'd14_proj',     'd14_proj', '{"proj":3}',         null, null, __g1, 'read', false),
        ('d14', 'd14', __t, 'd14_proj.doc', 'd14_proj', '{"proj":3,"doc":1}', null, __u,  null, 'read', true),
    -- proj 4: group DENY on the project, user GRANT on doc 2
        ('d14', 'd14', __t, 'd14_proj',     'd14_proj', '{"proj":4}',         null, null, __g1, 'read', true),
        ('d14', 'd14', __t, 'd14_proj.doc', 'd14_proj', '{"proj":4,"doc":2}', null, __u,  null, 'read', false),
    -- proj 5: user GRANT on the project only - covers its docs
        ('d14', 'd14', __t, 'd14_proj',     'd14_proj', '{"proj":5}',         null, __u,  null, 'read', false),
    -- proj 6: G1 DENY on the doc type for the whole project (partial key), G2 GRANT on the project
        ('d14', 'd14', __t, 'd14_proj.doc', 'd14_proj', '{"proj":6}',         null, null, __g1, 'read', true),
        ('d14', 'd14', __t, 'd14_proj',     'd14_proj', '{"proj":6}',         null, null, __g2, 'read', false),
    -- proj 7: write only - read must stay denied
        ('d14', 'd14', __t, 'd14_proj',     'd14_proj', '{"proj":7}',         null, __u,  null, 'write', false),
    -- paths: user GRANT on a.b, group DENY on x, user GRANT on x.y
        ('d14', 'd14', __t, 'd14_fs',       'd14_fs',   '{}', 'a.b', __u,  null, 'read', false),
        ('d14', 'd14', __t, 'd14_fs',       'd14_fs',   '{}', 'x',   null, __g2, 'read', true),
        ('d14', 'd14', __t, 'd14_fs',       'd14_fs',   '{}', 'x.y', __u,  null, 'read', false);

    create temp table if not exists _d14 (key text primary key, val text);
    delete from _d14;
    insert into _d14 values ('t', __t::text), ('u', __u::text), ('g1', __g1::text), ('g2', __g2::text);

    -- expected read access per candidate
    create temp table if not exists _d14_expect (resource_type text, resource_id jsonb, resource_path text, expected boolean, why text);
    delete from _d14_expect;
    insert into _d14_expect values
        ('d14_proj.doc', '{"proj":1,"doc":5}', null, false, 'user deny on the project beats user grant on the doc'),
        ('d14_proj.doc', '{"proj":2,"doc":7}', null, true,  'partial key {proj:2} on the doc type covers doc 7'),
        ('d14_proj.doc', '{"proj":3,"doc":1}', null, false, 'user deny on the doc beats group grant on the project'),
        ('d14_proj.doc', '{"proj":3,"doc":9}', null, true,  'group grant on the project covers another doc'),
        ('d14_proj.doc', '{"proj":4,"doc":2}', null, false, 'group deny on the project beats user grant on the doc'),
        ('d14_proj.doc', '{"proj":5,"doc":3}', null, true,  'user grant on the project covers its docs'),
        ('d14_proj',     '{"proj":5}',         null, true,  'user grant on the project itself'),
        ('d14_proj.doc', '{"proj":6,"doc":4}', null, false, 'G1 deny on all docs of the project beats G2 grant on the project'),
        ('d14_proj',     '{"proj":6}',         null, true,  'the G1 deny is on docs only; the project itself stays readable'),
        ('d14_proj.doc', '{"proj":7,"doc":1}', null, false, 'a write grant gives no read'),
        ('d14_proj.doc', '{"proj":8,"doc":1}', null, false, 'no rules at all'),
        ('d14_fs',       '{}',                 'a.b.c', true,  'path grant on a.b covers a.b.c'),
        ('d14_fs',       '{}',                 'a.c',   false, 'path grant on a.b does not cover a.c'),
        ('d14_fs',       '{}',                 'x.y.z', false, 'group deny on path x beats user grant on x.y');

    raise notice 'SETUP: T=%, U=%, G1=%, G2=%', __t, __u, __g1, __g2;
end $$;

create or replace function pg_temp.d14(_key text) returns text language sql as $$ select val from _d14 where key = _key $$;
