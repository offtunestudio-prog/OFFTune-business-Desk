-- OFFTune hosted migration foundation.
-- Business records are intentionally not included yet: they need their own
-- tenant-scoped schema and role policies before any real data is moved.

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
grant usage on schema private to authenticated;

create table public.workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(trim(name)) between 1 and 120),
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null check (char_length(trim(display_name)) between 1 and 120),
  avatar_path text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.workspace_members (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('owner', 'manager', 'employee')),
  manager_user_id uuid references auth.users(id) on delete set null,
  is_active boolean not null default true,
  joined_at timestamptz not null default now(),
  unique (workspace_id, user_id),
  check (manager_user_id is null or manager_user_id <> user_id),
  check (role <> 'owner' or manager_user_id is null)
);

create unique index workspace_members_one_owner_per_workspace
  on public.workspace_members (workspace_id)
  where role = 'owner';
create index workspace_members_user_active_idx
  on public.workspace_members (user_id, is_active, workspace_id);
create index workspace_members_manager_idx
  on public.workspace_members (workspace_id, manager_user_id)
  where manager_user_id is not null;

create function private.is_workspace_member(p_workspace_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.workspace_members m
    where m.workspace_id = p_workspace_id
      and m.user_id = (select auth.uid())
      and m.is_active
  );
$$;

create function private.is_workspace_owner(p_workspace_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.workspace_members m
    where m.workspace_id = p_workspace_id
      and m.user_id = (select auth.uid())
      and m.role = 'owner'
      and m.is_active
  );
$$;

create function private.can_view_workspace_member(p_workspace_id uuid, p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.workspace_members viewer
    join public.workspace_members subject
      on subject.workspace_id = viewer.workspace_id
    where viewer.workspace_id = p_workspace_id
      and viewer.user_id = (select auth.uid())
      and viewer.is_active
      and subject.user_id = p_user_id
      and subject.is_active
      and (
        viewer.role = 'owner'
        or subject.user_id = viewer.user_id
        or (viewer.role = 'manager' and subject.manager_user_id = viewer.user_id)
      )
  );
$$;

create function private.can_manage_workspace_members(p_workspace_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select private.is_workspace_owner(p_workspace_id);
$$;

create function private.can_view_profile(p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select p_user_id = (select auth.uid()) or exists (
    select 1
    from public.workspace_members viewer
    join public.workspace_members subject
      on subject.workspace_id = viewer.workspace_id
    where viewer.user_id = (select auth.uid())
      and viewer.is_active
      and subject.user_id = p_user_id
      and subject.is_active
      and (
        viewer.role = 'owner'
        or subject.user_id = viewer.user_id
        or (viewer.role = 'manager' and subject.manager_user_id = viewer.user_id)
      )
  );
$$;

create function private.bootstrap_workspace_owner()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.workspace_members (workspace_id, user_id, role)
  values (new.id, new.created_by, 'owner');
  return new;
end;
$$;

create trigger workspaces_bootstrap_owner
  after insert on public.workspaces
  for each row execute function private.bootstrap_workspace_owner();

create function private.validate_workspace_manager()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.manager_user_id is not null and not exists (
    select 1
    from public.workspace_members manager
    where manager.workspace_id = new.workspace_id
      and manager.user_id = new.manager_user_id
      and manager.role in ('owner', 'manager')
      and manager.is_active
  ) then
    raise exception 'Manager must be an active owner or manager in the same workspace';
  end if;
  return new;
end;
$$;

create function private.prevent_workspace_owner_demotion()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if old.role = 'owner'
     and (new.role <> 'owner' or new.workspace_id <> old.workspace_id or new.user_id <> old.user_id) then
    raise exception 'Transfer workspace ownership through the dedicated ownership process';
  end if;
  return new;
end;
$$;

create trigger workspace_members_validate_manager
  before insert or update of workspace_id, manager_user_id
  on public.workspace_members
  for each row execute function private.validate_workspace_manager();
create trigger workspace_members_protect_owner
  before update on public.workspace_members
  for each row execute function private.prevent_workspace_owner_demotion();

revoke all on function private.is_workspace_member(uuid) from public, anon;
revoke all on function private.is_workspace_owner(uuid) from public, anon;
revoke all on function private.can_view_workspace_member(uuid, uuid) from public, anon;
revoke all on function private.can_manage_workspace_members(uuid) from public, anon;
revoke all on function private.can_view_profile(uuid) from public, anon;
revoke all on function private.bootstrap_workspace_owner() from public, anon, authenticated;
revoke all on function private.validate_workspace_manager() from public, anon, authenticated;
revoke all on function private.prevent_workspace_owner_demotion() from public, anon, authenticated;
grant execute on function private.is_workspace_member(uuid) to authenticated;
grant execute on function private.is_workspace_owner(uuid) to authenticated;
grant execute on function private.can_view_workspace_member(uuid, uuid) to authenticated;
grant execute on function private.can_manage_workspace_members(uuid) to authenticated;
grant execute on function private.can_view_profile(uuid) to authenticated;

alter table public.workspaces enable row level security;
alter table public.profiles enable row level security;
alter table public.workspace_members enable row level security;

revoke all on table public.workspaces, public.profiles, public.workspace_members from anon, authenticated;
grant select, insert, update on table public.workspaces to authenticated;
grant select, insert, update on table public.profiles to authenticated;
grant select, insert, update, delete on table public.workspace_members to authenticated;

create policy workspaces_select_member
  on public.workspaces for select to authenticated
  using ((select private.is_workspace_member(id)));
create policy workspaces_insert_self
  on public.workspaces for insert to authenticated
  with check (created_by = (select auth.uid()));
create policy workspaces_update_owner
  on public.workspaces for update to authenticated
  using ((select private.is_workspace_owner(id)))
  with check ((select private.is_workspace_owner(id)));

create policy profiles_select_self_or_team
  on public.profiles for select to authenticated
  using ((select private.can_view_profile(user_id)));
create policy profiles_insert_self
  on public.profiles for insert to authenticated
  with check (user_id = (select auth.uid()));
create policy profiles_update_self
  on public.profiles for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

create policy workspace_members_select_scoped
  on public.workspace_members for select to authenticated
  using ((select private.can_view_workspace_member(workspace_id, user_id)));
create policy workspace_members_insert_owner
  on public.workspace_members for insert to authenticated
  with check ((select private.can_manage_workspace_members(workspace_id)));
create policy workspace_members_update_owner
  on public.workspace_members for update to authenticated
  using ((select private.can_manage_workspace_members(workspace_id)))
  with check ((select private.can_manage_workspace_members(workspace_id)));
create policy workspace_members_delete_non_owner
  on public.workspace_members for delete to authenticated
  using (
    role <> 'owner'
    and (select private.can_manage_workspace_members(workspace_id))
  );
