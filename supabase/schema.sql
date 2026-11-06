-- Mediprice Bangladesh: secure admin database
-- Run once in the Supabase SQL Editor after creating the project.

create extension if not exists pgcrypto;

create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'admin' check (role = 'admin'),
  created_at timestamptz not null default now()
);

create table if not exists public.price_items (
  id uuid primary key default gen_random_uuid(),
  type text not null check (type in ('medicine', 'test')),
  name_bn text not null,
  name_en text,
  generic_name text,
  strength text,
  institution text not null default '',
  city text not null default '',
  price_bdt numeric(12,2),
  unit text,
  verified_date date,
  source text,
  notes text,
  is_published boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint price_nonnegative check (price_bdt is null or price_bdt >= 0)
);

create index if not exists price_items_type_idx on public.price_items(type);
create index if not exists price_items_published_idx on public.price_items(is_published);
create index if not exists price_items_name_bn_idx on public.price_items using gin (to_tsvector('simple', coalesce(name_bn, '')));
create index if not exists price_items_name_en_idx on public.price_items using gin (to_tsvector('simple', coalesce(name_en, '')));

create or replace function public.is_mediprice_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.admin_users
    where user_id = (select auth.uid()) and role = 'admin'
  );
$$;

create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists price_items_updated_at on public.price_items;
create trigger price_items_updated_at
before update on public.price_items
for each row execute function public.set_updated_at();

alter table public.admin_users enable row level security;
alter table public.price_items enable row level security;

drop policy if exists "Admins can read their own admin record" on public.admin_users;
create policy "Admins can read their own admin record"
on public.admin_users for select
to authenticated
using (user_id = (select auth.uid()) or public.is_mediprice_admin());

drop policy if exists "Public can read published prices" on public.price_items;
create policy "Public can read published prices"
on public.price_items for select
to anon, authenticated
using (is_published = true or public.is_mediprice_admin());

drop policy if exists "Admins can insert price items" on public.price_items;
create policy "Admins can insert price items"
on public.price_items for insert
to authenticated
with check (public.is_mediprice_admin());

drop policy if exists "Admins can update price items" on public.price_items;
create policy "Admins can update price items"
on public.price_items for update
to authenticated
using (public.is_mediprice_admin())
with check (public.is_mediprice_admin());

drop policy if exists "Admins can delete price items" on public.price_items;
create policy "Admins can delete price items"
on public.price_items for delete
to authenticated
using (public.is_mediprice_admin());

-- IMPORTANT: create the first user in Supabase Authentication, then add that
-- user's UUID to admin_users using the SQL Editor. Never expose service_role keys.
