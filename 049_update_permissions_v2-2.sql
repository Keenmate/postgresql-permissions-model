/*
 * PostgreSQL Permissions Model — update v2.2
 * ==========================================
 *
 *  - public.check_version: 002 creates check_version(text, text) and 018 adds
 *    check_version(text, text, boolean) next to it instead of replacing it. With
 *    both overloads present, any call with one or two arguments fails with
 *    "function public.check_version(unknown, unknown) is not unique". Drop the old
 *    two-argument overload (what versions_management v1.1 used to do).
 *  - versions_management 1.1 (check_version _throw_err) and 1.2 (get_version) are
 *    part of the v2 baseline in 018, but were never recorded in __version. Record
 *    them so check_version / get_version report the component correctly.
 */

set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

select *
from public.start_version_update('2.2', 'Drop ambiguous check_version overload',
                                 _component := 'postgresql_permissionmodel',
                                 _description := 'Drop public.check_version(text, text) left over from 002; record versions_management 1.1 and 1.2 (already in 018) in __version.');


drop function if exists public.check_version(_version text, _component text);


-- 1.1 gets an earlier timestamp so get_version reports 1.2 as the latest
insert into public.__version(component, version, title, description, execution_started, execution_finished)
values ('versions_management', '1.1', 'Check version can now throw exception to stop futher processing',
        'Included in the v2 baseline (018_functions_public.sql); recorded by 049_update_permissions_v2-2.sql.', now() - interval '1 second', now() - interval '1 second'),
       ('versions_management', '1.2', 'Get version detail, by component and by version (or the last one)',
        'Included in the v2 baseline (018_functions_public.sql); recorded by 049_update_permissions_v2-2.sql.', now(), now())
on conflict (component, version) do nothing;


select *
from public.stop_version_update('2.2', _component := 'postgresql_permissionmodel');
