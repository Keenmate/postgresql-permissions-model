set search_path = public, const, ext, stage, helpers, internal, unsecure, auth, triggers;

-- ============================================================================
-- API keys: admin_b calls with A's key id and _tenant_id = B.
-- Every call raises 30007 (API key not found) and A's key is unchanged.
-- ============================================================================
do $$
begin
    raise notice '';
    raise notice '--- 002: API keys of tenant A, called with _tenant_id = B ---';

    perform pg_temp.a02_expect('assign_api_key_permissions',
        'select * from auth.assign_api_key_permissions(''t'', {admin_b_id}, ''c'', {key_a_id}, ''a02_admin'', null, {b_id})', '30007');
    perform pg_temp.a02_expect('unassign_api_key_permissions',
        'select * from auth.unassign_api_key_permissions(''t'', {admin_b_id}, ''c'', {key_a_id}, ''a02_admin'', null, {b_id})', '30007');
    perform pg_temp.a02_expect('update_api_key',
        'select * from auth.update_api_key(''t'', {admin_b_id}, ''c'', {key_a_id}, ''hijacked'', null, null, null, {b_id})', '30007');
    perform pg_temp.a02_expect('update_api_key_secret',
        'select * from auth.update_api_key_secret(''t'', {admin_b_id}, ''c'', {key_a_id}, ''a02-new-secret'', {b_id})', '30007');
    perform pg_temp.a02_expect('delete_api_key',
        'select * from auth.delete_api_key(''t'', {admin_b_id}, ''c'', {key_a_id}, {b_id})', '30007');
end $$;

do $$
declare
    __key_a    int    := pg_temp.a02('key_a_id')::int;
    __k        record;
    __api_user bigint;
begin
    select ak.title, ak.secret_hash, ak.tenant_id from auth.api_key ak where ak.api_key_id = __key_a into __k;
    if __k.tenant_id is null then
        raise notice 'FAIL: A''s API key was deleted';
    else
        raise notice 'PASS: A''s API key still exists';
        if __k.title = 'hijacked' then
            raise notice 'FAIL: A''s API key title was changed';
        else
            raise notice 'PASS: A''s API key title is unchanged';
        end if;
        if __k.secret_hash = auth.generate_api_secret_hash('a02-new-secret') then
            raise notice 'FAIL: A''s API key secret was replaced';
        else
            raise notice 'PASS: A''s API key secret is unchanged';
        end if;
    end if;

    select ui.user_id from auth.api_key ak
        inner join auth.user_info ui on ui.code = auth.generate_api_key_username(ak.api_key)
    where ak.api_key_id = __key_a into __api_user;
    if exists(select from auth.permission_assignment where user_id = __api_user) then
        raise notice 'FAIL: A''s API key user got a permission assignment';
    else
        raise notice 'PASS: A''s API key user has no permission assignment';
    end if;
end $$;

-- Own tenant still works: admin_b updates and rotates B's key
do $$
declare
    __b      int    := pg_temp.a02('b_id')::int;
    __key_b  int    := pg_temp.a02('key_b_id')::int;
    __admin  bigint := pg_temp.a02('admin_b_id')::bigint;
    __title  text;
    __secret text;
begin
    select k.__title from auth.update_api_key('t', __admin, 'c', __key_b, 'A02 key B renamed', null, null, null, __b) k into __title;
    if __title = 'A02 key B renamed' then
        raise notice 'PASS: own tenant: update_api_key';
    else
        raise notice 'FAIL: own tenant: update_api_key returned %', __title;
    end if;

    select k.__api_secret from auth.update_api_key_secret('t', __admin, 'c', __key_b, 'a02-own-secret', __b) k into __secret;
    if __secret = 'a02-own-secret'
        and (select secret_hash from auth.api_key where api_key_id = __key_b) = auth.generate_api_secret_hash('a02-own-secret') then
        raise notice 'PASS: own tenant: update_api_key_secret stored the new secret';
    else
        raise notice 'FAIL: own tenant: update_api_key_secret';
    end if;
end $$;
