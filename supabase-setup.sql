-- Run this in your Supabase project → SQL Editor

-- 1. Create the vault_entries table
create table if not exists vault_entries (
  id          text primary key,
  encrypted   text not null,
  category    text not null default 'other',
  updated_at  timestamptz default now()
);

-- 2. Create vault_config table (stores security question etc.)
create table if not exists vault_config (
  key   text primary key,
  value text not null
);

-- 3. Enable Row Level Security
alter table vault_entries enable row level security;
alter table vault_config  enable row level security;

-- 4. vault_entries policies
create policy "Read all entries"
  on vault_entries for select
  using (true);

create policy "Write entries"
  on vault_entries for all
  using (true)
  with check (true);

-- 5. vault_config policies
create policy "Read config"
  on vault_config for select
  using (true);

create policy "Write config"
  on vault_config for all
  using (true)
  with check (true);
