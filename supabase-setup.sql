-- Run this in your Supabase project → SQL Editor

-- 1. Create the vault_entries table
create table if not exists vault_entries (
  id          text primary key,
  encrypted   text not null,
  category    text not null default 'other',
  updated_at  timestamptz default now()
);

-- 2. Enable Row Level Security
alter table vault_entries enable row level security;

-- 3. Allow anyone with the anon key to read (for the Vercel web app)
create policy "Read all entries"
  on vault_entries for select
  using (true);

-- 4. Allow anyone with the anon key to insert/update/delete
--    (your CLI uses the anon key too — no user auth needed since
--     data is already encrypted with your master password)
create policy "Write entries"
  on vault_entries for all
  using (true)
  with check (true);
