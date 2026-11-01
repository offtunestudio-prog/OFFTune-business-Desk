create index workspaces_created_by_idx
  on public.workspaces (created_by);

create index workspace_members_manager_user_idx
  on public.workspace_members (manager_user_id)
  where manager_user_id is not null;
