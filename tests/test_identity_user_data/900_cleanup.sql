-- transaction isolation rolls everything back
do $$ begin raise notice 'Identity user data - done'; end $$;
