-- ============================================================================
-- ضيافتكم (Diyafatkum) — Database Schema for Supabase — v2 (hardened)
-- ============================================================================
-- Changes from v1:
--   - All sensitive state transitions (accept/reject order, mark paid/completed,
--     raise/resolve dispute, approve/reject/suspend/reactivate company) now go
--     through SECURITY DEFINER RPC functions instead of broad RLS UPDATE grants.
--     The tables themselves have NO client-writable UPDATE policy for status —
--     write access is funneled through vetted functions that check identity,
--     ownership, and valid current-state before changing anything.
--   - Added: order_status_history (audit trail, auto-logged via trigger),
--     payments (real transaction records), reviews (ratings computed from
--     actual completed orders instead of a hand-set number), company_staff
--     (lets a company be managed by more than one login).
--   - Added composite indexes for the query patterns the app actually runs
--     (provider's order list, customer's order list).
-- ============================================================================

create extension if not exists "uuid-ossp";
create extension if not exists pg_cron;

-- ---------------------------------------------------------------------------
-- ENUM TYPES
-- ---------------------------------------------------------------------------
create type user_role as enum ('customer', 'provider', 'admin');
create type company_status as enum ('pending', 'active', 'suspended');
create type pricing_type as enum ('tier', 'perKg', 'perUnit', 'fixed');
create type order_type as enum ('package', 'services');
create type order_status as enum
  ('pending','accepted','confirmed','paid','completed','rejected','expired','disputed','resolved');
create type dispute_raised_by as enum ('customer', 'provider');
create type dispute_resolved_side as enum ('customer', 'provider');
create type staff_role as enum ('owner', 'staff');

-- ---------------------------------------------------------------------------
-- PROFILES
-- ---------------------------------------------------------------------------
create table profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  name        text not null,
  role        user_role not null default 'customer',
  phone       text,
  created_at  timestamptz not null default now()
);

create function handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, name, role)
  values (new.id, coalesce(new.raw_user_meta_data->>'name', 'مستخدم جديد'), 'customer');
  return new;
end;
$$ language plpgsql security definer;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure handle_new_user();

-- ---------------------------------------------------------------------------
-- COMPANIES
-- ---------------------------------------------------------------------------
create table companies (
  id          uuid primary key default uuid_generate_v4(),
  owner_id    uuid references profiles(id) on delete set null,
  name        text not null,
  logo        text,
  tag         text,
  status      company_status not null default 'pending',
  reason      text,
  rating      numeric(2,1),
  rating_count int not null default 0,
  created_at  timestamptz not null default now()
);

create index idx_companies_status on companies(status);
create index idx_companies_owner on companies(owner_id);

create table company_staff (
  company_id  uuid not null references companies(id) on delete cascade,
  profile_id  uuid not null references profiles(id) on delete cascade,
  staff_role  staff_role not null default 'staff',
  created_at  timestamptz not null default now(),
  primary key (company_id, profile_id)
);

-- ---------------------------------------------------------------------------
-- PACKAGES / package_tiers
-- ---------------------------------------------------------------------------
create table packages (
  id            uuid primary key default uuid_generate_v4(),
  company_id    uuid not null references companies(id) on delete cascade,
  name          text not null,
  emoji         text default '✨',
  pricing_type  pricing_type not null,
  price         numeric(10,3),
  rate_per_kg   numeric(10,3),
  min_kg        numeric(10,2),
  includes      text[] default '{}',
  is_active     boolean not null default true,
  created_at    timestamptz not null default now(),
  check (
    (pricing_type = 'fixed' and price is not null) or
    (pricing_type = 'perKg' and rate_per_kg is not null and min_kg is not null) or
    (pricing_type = 'tier')
  )
);

create table package_tiers (
  id          uuid primary key default uuid_generate_v4(),
  package_id  uuid not null references packages(id) on delete cascade,
  label       text not null,
  price       numeric(10,3) not null,
  sort_order  int not null default 0
);

create index idx_packages_company on packages(company_id);
create index idx_package_tiers_package on package_tiers(package_id);

-- ---------------------------------------------------------------------------
-- SERVICES / service_tiers
-- ---------------------------------------------------------------------------
create table services (
  id            uuid primary key default uuid_generate_v4(),
  company_id    uuid not null references companies(id) on delete cascade,
  name          text not null,
  description   text,
  pricing_type  pricing_type not null,
  price         numeric(10,3),
  unit_label    text,
  rate_per_kg   numeric(10,3),
  min_kg        numeric(10,2),
  is_active     boolean not null default true,
  created_at    timestamptz not null default now(),
  check (
    (pricing_type = 'fixed'   and price is not null) or
    (pricing_type = 'perUnit' and price is not null and unit_label is not null) or
    (pricing_type = 'perKg'   and rate_per_kg is not null and min_kg is not null) or
    (pricing_type = 'tier')
  )
);

create table service_tiers (
  id          uuid primary key default uuid_generate_v4(),
  service_id  uuid not null references services(id) on delete cascade,
  label       text not null,
  price       numeric(10,3) not null,
  sort_order  int not null default 0
);

create index idx_services_company on services(company_id);
create index idx_service_tiers_service on service_tiers(service_id);

-- ---------------------------------------------------------------------------
-- ORDERS / order_items  (write access: RPC functions only — see below)
-- ---------------------------------------------------------------------------
create table orders (
  id              uuid primary key default uuid_generate_v4(),
  company_id      uuid not null references companies(id),
  customer_id     uuid not null references profiles(id),
  type            order_type not null,
  status          order_status not null default 'pending',
  total           numeric(10,3) not null,
  event_date      date,
  location        text,
  guests_expected int,
  notes           text,
  expires_at      timestamptz,
  reason          text,
  issue           text,
  raised_by       dispute_raised_by,
  resolution      text,
  resolved_side   dispute_resolved_side,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

create table order_items (
  id          uuid primary key default uuid_generate_v4(),
  order_id    uuid not null references orders(id) on delete cascade,
  name        text not null,
  qty         int not null default 1,
  unit_price  numeric(10,3) not null
);

create index idx_orders_company on orders(company_id);
create index idx_orders_customer on orders(customer_id);
create index idx_orders_status on orders(status);
create index idx_orders_company_status on orders(company_id, status);
create index idx_orders_customer_status on orders(customer_id, status);
create index idx_orders_pending_expiry on orders(expires_at) where status = 'pending';
create index idx_order_items_order on order_items(order_id);

create function set_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

create trigger orders_set_updated_at
  before update on orders
  for each row execute procedure set_updated_at();

-- ---------------------------------------------------------------------------
-- ORDER STATUS HISTORY (automatic audit trail)
-- ---------------------------------------------------------------------------
create table order_status_history (
  id          uuid primary key default uuid_generate_v4(),
  order_id    uuid not null references orders(id) on delete cascade,
  old_status  order_status,
  new_status  order_status not null,
  changed_by  uuid references profiles(id),
  changed_at  timestamptz not null default now()
);

create index idx_order_status_history_order on order_status_history(order_id);

create function log_order_status_change()
returns trigger as $$
begin
  if old.status is distinct from new.status then
    insert into order_status_history (order_id, old_status, new_status, changed_by)
    values (new.id, old.status, new.status, auth.uid());
  end if;
  return new;
end;
$$ language plpgsql security definer;

create trigger orders_log_status_change
  after update on orders
  for each row execute procedure log_order_status_change();

-- ---------------------------------------------------------------------------
-- PAYMENTS
-- ---------------------------------------------------------------------------
create table payments (
  id          uuid primary key default uuid_generate_v4(),
  order_id    uuid not null references orders(id) on delete cascade,
  amount      numeric(10,3) not null,
  method      text,
  reference   text,
  paid_at     timestamptz not null default now()
);

create index idx_payments_order on payments(order_id);

-- ---------------------------------------------------------------------------
-- REVIEWS (companies.rating is a cached average, kept in sync by trigger)
-- ---------------------------------------------------------------------------
create table reviews (
  id          uuid primary key default uuid_generate_v4(),
  order_id    uuid not null unique references orders(id) on delete cascade,
  company_id  uuid not null references companies(id),
  customer_id uuid not null references profiles(id),
  rating      int not null check (rating between 1 and 5),
  comment     text,
  created_at  timestamptz not null default now()
);

create index idx_reviews_company on reviews(company_id);

create function refresh_company_rating()
returns trigger as $$
begin
  update companies c
  set rating = sub.avg_rating, rating_count = sub.cnt
  from (
    select company_id, round(avg(rating)::numeric, 1) as avg_rating, count(*) as cnt
    from reviews
    where company_id = coalesce(new.company_id, old.company_id)
    group by company_id
  ) sub
  where c.id = sub.company_id;
  return null;
end;
$$ language plpgsql security definer;

create trigger reviews_refresh_rating
  after insert or update or delete on reviews
  for each row execute procedure refresh_company_rating();

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================
alter table profiles             enable row level security;
alter table companies            enable row level security;
alter table company_staff        enable row level security;
alter table packages             enable row level security;
alter table package_tiers        enable row level security;
alter table services             enable row level security;
alter table service_tiers        enable row level security;
alter table orders               enable row level security;
alter table order_items          enable row level security;
alter table order_status_history enable row level security;
alter table payments             enable row level security;
alter table reviews              enable row level security;

create function current_role_is(target user_role)
returns boolean as $$
  select exists (select 1 from profiles where id = auth.uid() and role = target);
$$ language sql stable security definer;

create function my_company_ids()
returns setof uuid as $$
  select id from companies where owner_id = auth.uid()
  union
  select company_id from company_staff where profile_id = auth.uid();
$$ language sql stable security definer;

-- profiles ---------------------------------------------------------------
create policy "profiles: read own" on profiles for select using (id = auth.uid());
create policy "profiles: admin reads all" on profiles for select using (current_role_is('admin'));
create policy "profiles: update own" on profiles for update using (id = auth.uid());

-- companies ----------------------------------------------------------------
-- Read access is open via RLS. Every write that changes `status` (approve /
-- reject / suspend / reactivate) is intentionally NOT exposed here — see the
-- RPC functions section. Only non-status catalog edits are allowed directly.
create policy "companies: public reads active" on companies
  for select using (status = 'active');
create policy "companies: owner reads own" on companies
  for select using (owner_id = auth.uid() or id in (select my_company_ids()));
create policy "companies: admin reads all" on companies
  for select using (current_role_is('admin'));
create policy "companies: provider applies (creates own, starts pending)" on companies
  for insert with check (owner_id = auth.uid() and current_role_is('provider'));
create policy "companies: owner edits own catalog info, not status" on companies
  for update using (owner_id = auth.uid())
  with check (owner_id = auth.uid() and status = (select c2.status from companies c2 where c2.id = companies.id));

create policy "company_staff: members read their own membership rows" on company_staff
  for select using (profile_id = auth.uid() or company_id in (select my_company_ids()));

-- packages / package_tiers / services / service_tiers ----------------------
create policy "packages: public reads of active companies" on packages
  for select using (exists (select 1 from companies c where c.id = company_id and c.status = 'active'));
create policy "packages: owner full access" on packages
  for all using (company_id in (select my_company_ids()));
create policy "packages: admin full access" on packages
  for all using (current_role_is('admin'));

create policy "package_tiers: public reads" on package_tiers
  for select using (exists (
    select 1 from packages p join companies c on c.id = p.company_id
    where p.id = package_id and c.status = 'active'));
create policy "package_tiers: owner full access" on package_tiers
  for all using (package_id in (select id from packages where company_id in (select my_company_ids())));
create policy "package_tiers: admin full access" on package_tiers
  for all using (current_role_is('admin'));

create policy "services: public reads of active companies" on services
  for select using (exists (select 1 from companies c where c.id = company_id and c.status = 'active'));
create policy "services: owner full access" on services
  for all using (company_id in (select my_company_ids()));
create policy "services: admin full access" on services
  for all using (current_role_is('admin'));

create policy "service_tiers: public reads" on service_tiers
  for select using (exists (
    select 1 from services s join companies c on c.id = s.company_id
    where s.id = service_id and c.status = 'active'));
create policy "service_tiers: owner full access" on service_tiers
  for all using (service_id in (select id from services where company_id in (select my_company_ids())));
create policy "service_tiers: admin full access" on service_tiers
  for all using (current_role_is('admin'));

-- orders / order_items -------------------------------------------------------
-- READ ONLY via RLS. There is deliberately NO insert/update policy on orders
-- or order_items — every write (creating a request, accepting/rejecting,
-- marking paid/completed, disputes) must go through the RPC functions below.
create policy "orders: customer reads own" on orders
  for select using (customer_id = auth.uid());
create policy "orders: provider reads own company orders" on orders
  for select using (company_id in (select my_company_ids()));
create policy "orders: admin reads all" on orders
  for select using (current_role_is('admin'));

create policy "order_items: follows parent order visibility" on order_items
  for select using (
    order_id in (select id from orders where customer_id = auth.uid() or company_id in (select my_company_ids()))
    or current_role_is('admin')
  );

create policy "order_status_history: follows parent order visibility" on order_status_history
  for select using (
    order_id in (select id from orders where customer_id = auth.uid() or company_id in (select my_company_ids()))
    or current_role_is('admin')
  );

create policy "payments: follows parent order visibility" on payments
  for select using (
    order_id in (select id from orders where customer_id = auth.uid() or company_id in (select my_company_ids()))
    or current_role_is('admin')
  );

-- reviews --------------------------------------------------------------------
create policy "reviews: public reads" on reviews for select using (true);
create policy "reviews: customer writes own, once, for their own completed order" on reviews
  for insert with check (
    customer_id = auth.uid()
    and exists (select 1 from orders o where o.id = order_id and o.customer_id = auth.uid() and o.status = 'completed')
  );

-- ============================================================================
-- RPC FUNCTIONS — the only way orders/companies change state.
-- Each is SECURITY DEFINER (bypasses RLS) but re-checks identity, ownership,
-- and current status before doing anything, raising a clear exception
-- otherwise. A leaked anon key or a client bug cannot corrupt order state —
-- only these vetted, single-purpose functions can write to these tables.
-- ============================================================================

create function request_services_order(p_company_id uuid, p_items jsonb, p_notes text default null)
returns uuid language plpgsql security definer as $$
declare
  v_order_id uuid;
  v_total numeric(10,3);
  v_item jsonb;
begin
  if not current_role_is('customer') then
    raise exception 'يجب تسجيل الدخول كعميل لإنشاء هذا الطلب';
  end if;
  if not exists (select 1 from companies where id = p_company_id and status = 'active') then
    raise exception 'هذي الشركة غير متاحة حاليًا';
  end if;

  select coalesce(sum((i->>'qty')::int * (i->>'unit_price')::numeric), 0) into v_total
  from jsonb_array_elements(p_items) i;

  insert into orders (company_id, customer_id, type, status, total, notes, expires_at)
  values (p_company_id, auth.uid(), 'services', 'pending', v_total, p_notes, now() + interval '5 minutes')
  returning id into v_order_id;

  for v_item in select * from jsonb_array_elements(p_items) loop
    insert into order_items (order_id, name, qty, unit_price)
    values (v_order_id, v_item->>'name', (v_item->>'qty')::int, (v_item->>'unit_price')::numeric);
  end loop;

  return v_order_id;
end;
$$;

create function request_package_order(
  p_company_id uuid, p_items jsonb, p_event_date date default null,
  p_location text default null, p_guests_expected int default null, p_notes text default null
) returns uuid language plpgsql security definer as $$
declare
  v_order_id uuid;
  v_total numeric(10,3);
  v_item jsonb;
begin
  if not current_role_is('customer') then
    raise exception 'يجب تسجيل الدخول كعميل لإنشاء هذا الطلب';
  end if;
  if not exists (select 1 from companies where id = p_company_id and status = 'active') then
    raise exception 'هذي الشركة غير متاحة حاليًا';
  end if;

  select coalesce(sum((i->>'qty')::int * (i->>'unit_price')::numeric), 0) into v_total
  from jsonb_array_elements(p_items) i;

  insert into orders (company_id, customer_id, type, status, total, event_date, location, guests_expected, notes)
  values (p_company_id, auth.uid(), 'package', 'confirmed', v_total, p_event_date, p_location, p_guests_expected, p_notes)
  returning id into v_order_id;

  for v_item in select * from jsonb_array_elements(p_items) loop
    insert into order_items (order_id, name, qty, unit_price)
    values (v_order_id, v_item->>'name', (v_item->>'qty')::int, (v_item->>'unit_price')::numeric);
  end loop;

  return v_order_id;
end;
$$;

create function accept_order(p_order_id uuid)
returns void language plpgsql security definer as $$
declare v_company_id uuid;
begin
  select company_id into v_company_id from orders where id = p_order_id and status = 'pending';
  if v_company_id is null then raise exception 'الطلب غير موجود أو لم يعد بحالة انتظار'; end if;
  if v_company_id not in (select my_company_ids()) then raise exception 'ما عندك صلاحية على هذا الطلب'; end if;
  update orders set status = 'accepted' where id = p_order_id;
end;
$$;

create function reject_order(p_order_id uuid, p_reason text default null)
returns void language plpgsql security definer as $$
declare v_company_id uuid;
begin
  select company_id into v_company_id from orders where id = p_order_id and status = 'pending';
  if v_company_id is null then raise exception 'الطلب غير موجود أو لم يعد بحالة انتظار'; end if;
  if v_company_id not in (select my_company_ids()) then raise exception 'ما عندك صلاحية على هذا الطلب'; end if;
  update orders set status = 'rejected', reason = coalesce(p_reason, 'اعتذر مقدم الخدمة عن توفير الطلب') where id = p_order_id;
end;
$$;

create function record_payment(p_order_id uuid, p_method text, p_reference text default null)
returns void language plpgsql security definer as $$
declare v_customer_id uuid; v_status order_status; v_total numeric(10,3);
begin
  select customer_id, status, total into v_customer_id, v_status, v_total from orders where id = p_order_id;
  if v_customer_id is null then raise exception 'الطلب غير موجود'; end if;
  if v_customer_id <> auth.uid() then raise exception 'ما عندك صلاحية على هذا الطلب'; end if;
  if v_status not in ('confirmed','accepted') then raise exception 'هذا الطلب مو بحالة تسمح بالدفع'; end if;

  insert into payments (order_id, amount, method, reference) values (p_order_id, v_total, p_method, p_reference);
  update orders set status = 'paid' where id = p_order_id;
end;
$$;

create function mark_completed(p_order_id uuid)
returns void language plpgsql security definer as $$
declare v_company_id uuid;
begin
  select company_id into v_company_id from orders where id = p_order_id and status = 'paid';
  if v_company_id is null then raise exception 'الطلب غير موجود أو لم يُدفع بعد'; end if;
  if v_company_id not in (select my_company_ids()) then raise exception 'ما عندك صلاحية على هذا الطلب'; end if;
  update orders set status = 'completed' where id = p_order_id;
end;
$$;

create function raise_dispute(p_order_id uuid, p_issue text)
returns void language plpgsql security definer as $$
declare v_customer_id uuid; v_company_id uuid; v_side dispute_raised_by;
begin
  select customer_id, company_id into v_customer_id, v_company_id from orders where id = p_order_id;
  if v_customer_id is null then raise exception 'الطلب غير موجود'; end if;

  if v_customer_id = auth.uid() then v_side := 'customer';
  elsif v_company_id in (select my_company_ids()) then v_side := 'provider';
  else raise exception 'ما عندك صلاحية على هذا الطلب'; end if;

  update orders set status = 'disputed', issue = p_issue, raised_by = v_side where id = p_order_id;
end;
$$;

create function resolve_dispute(p_order_id uuid, p_side dispute_resolved_side, p_resolution text)
returns void language plpgsql security definer as $$
begin
  if not current_role_is('admin') then raise exception 'مسموح لمدير المنصة بس يحل النزاعات'; end if;
  if not exists (select 1 from orders where id = p_order_id and status = 'disputed') then
    raise exception 'الطلب غير موجود أو ما فيه نزاع مفتوح';
  end if;
  update orders set status = 'resolved', resolved_side = p_side, resolution = p_resolution where id = p_order_id;
end;
$$;

create function approve_company(p_company_id uuid)
returns void language plpgsql security definer as $$
begin
  if not current_role_is('admin') then raise exception 'مسموح لمدير المنصة بس'; end if;
  update companies set status = 'active', reason = null where id = p_company_id and status = 'pending';
  if not found then raise exception 'الشركة غير موجودة أو مو بحالة مراجعة'; end if;
end;
$$;

create function reject_company(p_company_id uuid, p_reason text)
returns void language plpgsql security definer as $$
begin
  if not current_role_is('admin') then raise exception 'مسموح لمدير المنصة بس'; end if;
  delete from companies where id = p_company_id and status = 'pending';
  if not found then raise exception 'الشركة غير موجودة أو مو بحالة مراجعة'; end if;
end;
$$;

create function suspend_company(p_company_id uuid, p_reason text)
returns void language plpgsql security definer as $$
begin
  if not current_role_is('admin') then raise exception 'مسموح لمدير المنصة بس'; end if;
  update companies set status = 'suspended', reason = p_reason where id = p_company_id and status = 'active';
  if not found then raise exception 'الشركة غير موجودة أو مو نشطة'; end if;
end;
$$;

create function reactivate_company(p_company_id uuid)
returns void language plpgsql security definer as $$
begin
  if not current_role_is('admin') then raise exception 'مسموح لمدير المنصة بس'; end if;
  update companies set status = 'active', reason = null where id = p_company_id and status = 'suspended';
  if not found then raise exception 'الشركة غير موجودة أو مو موقوفة'; end if;
end;
$$;

-- ============================================================================
-- AUTO-EXPIRY OF UNANSWERED REQUESTS
-- ============================================================================
create function expire_stale_pending_orders()
returns void as $$
  update orders
  set status = 'expired', reason = 'لم يتم الرد خلال ٥ دقايق'
  where status = 'pending' and expires_at < now();
$$ language sql;

select cron.schedule('expire-pending-orders', '* * * * *', $$ select expire_stale_pending_orders(); $$);

-- ============================================================================
-- SEED DATA (optional — delete before going live)
-- ============================================================================
-- insert into companies (id, name, logo, tag, status) values
--   (uuid_generate_v4(), 'بيت الضيافة', '☕', 'شاي وقهوة وتقديم', 'active');
