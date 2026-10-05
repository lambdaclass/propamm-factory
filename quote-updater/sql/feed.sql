-- The `feed` schema: what the P&L dashboard needs and nothing on chain has. One file, one
-- writer: the updater compiles it in (include_str! in quote-updater/src/record.rs) and runs it
-- on every connect, so Deploy Pusher is what applies a change here. The backfill only checks
-- the tables exist. Every statement is idempotent; Ponder never touches this schema.
--
-- Addresses are lowercase hex everywhere in here, and the check constraints make a writer
-- that forgets so fail loudly instead of producing rows no join ever matches.

-- The two functions below read Ponder's tables in `public`. Postgres checks a SQL function's
-- body against those tables when the function is created, and the whole file runs as one
-- transaction, so on a database where the indexer has not built yet the check failed and
-- took the schema and both tables down with it (measured on a fresh database: nothing was
-- created). With the check off the function is stored as text and only fails when called,
-- which is the right time: Grafana shows that error, and the tables are there for the updater.
set check_function_bodies = off;

create schema if not exists feed;

-- "For symbol `symbol`, from second `ts` until the next row, the mid was `mid`." Rows are
-- written when the mid changes and at least once a minute, so the lookup for "the mid at
-- time T" is the newest row with ts <= T, never an exact second. `source` is 'book' (live,
-- from the updater's Binance stream, bid and ask filled) or 'kline' (backfilled candles).
create table if not exists feed.mids (
  symbol text not null check (symbol = upper(symbol)),
  ts bigint not null,
  mid double precision not null,
  bid double precision,
  ask double precision,
  source text not null,
  primary key (symbol, ts)
);

-- "Pool `prop_amm`'s vault `vault` held `balance` raw units of `token` at block
-- `block_number`", read at that block, with the block's own timestamp. Written when the
-- balance changes and at least every five minutes, so "the inventory during fill i" is the
-- newest row for that pool, vault and token with block_number <= the fill's block. Keyed by
-- vault as well as token: with vaults per pair, one token can sit in two vaults of one pool.
create table if not exists feed.vault_balances (
  prop_amm text not null check (prop_amm = lower(prop_amm)),
  vault text not null check (vault = lower(vault)),
  token text not null check (token = lower(token)),
  block_number bigint not null,
  ts bigint not null,
  balance numeric(78, 0) not null,
  primary key (prop_amm, vault, token, block_number)
);
-- The drawdown panel reads every vault in a time window, and the data API pages one vault
-- by time; the primary key starts with the pool, so neither could seek without these.
create index if not exists vault_balances_ts on feed.vault_balances (ts);
create index if not exists vault_balances_vault_ts on feed.vault_balances (prop_amm, vault, ts, block_number, token);

-- Every token the updater has seen in a vault: its on-chain symbol() and decimals(), so a
-- dashboard can name a token address and scale its amounts without a hand-typed list.
-- Written by the vault exporter the first time it resolves a token.
create table if not exists feed.tokens (
  address text primary key check (address = lower(address)),
  symbol text not null,
  decimals integer not null
);
-- The data API names a pair by its symbols (`WETH-USDC`) and looks the addresses up here.
create index if not exists tokens_symbol on feed.tokens (upper(symbol));

-- The working behind every update the updater published: "for lane `lane` of pool
-- `prop_amm`, the last update sent for block `block_number` was signed at `ts` from feed
-- mid `feed_mid` and went out as `published_mid` with half-spread `delta`". Last, because
-- builder mode re-sends a block's update whenever the feed moves inside its window; the
-- builder includes whichever it held, so what landed is `public.price_updates`, and this
-- row is what we were quoting and why. A volatile pair
-- also records its σ, the three spread terms and the skew; a fixed-spread pair leaves them
-- null. Every value is in **lane orientation** and human units, the way `price_updates`
-- carries them scaled: `published_mid` is that row's `mid / 10^price_decimals`. `label` is
-- the pair's on-chain symbols at the time, for humans; `lane` is the key.
create table if not exists feed.quotes (
  prop_amm text not null check (prop_amm = lower(prop_amm)),
  lane numeric(78, 0) not null,
  label text not null,
  block_number bigint not null,
  ts bigint not null,
  feed_mid double precision not null,
  published_mid double precision not null,
  delta double precision not null,
  skew double precision,
  sigma double precision,
  hold double precision,
  edge double precision,
  stale double precision,
  primary key (prop_amm, lane, block_number)
);
create index if not exists quotes_lane_ts on feed.quotes (lane, ts);
-- A registered pricer's declared diagnostics at that update, by name (`{"edge": 0.25,
-- ...}`): what a custom model was thinking, where the three volatile columns above are
-- the built-in's. Null for a built-in pricer. Added after the table existed, so an
-- `alter` rather than a column above: `add column if not exists` keeps every connect
-- idempotent, like the `create table` it follows.
alter table feed.quotes add column if not exists terms jsonb;
-- What a spread panel needs beside each quote, stamped by the updater when it
-- signed it, so the panel is one read of `quotes_lane_ts` and joins nothing: `balance0` and
-- `balance1` are the pair's vault holdings of token0 and token1 (address order, whole
-- tokens) as the vault exporter last read them, and `ref_mid` is the Binance mid of the
-- pair's market (`ETHUSDC` for WETH/USDC, the same symbol `marked_fills` marks against),
-- in lane orientation like every other price here. Null where the updater had no reading.
-- Rows written before these columns existed are filled once by the backfill
-- (`--only quotes`), from `vault_balances` and `mids` as the panel used to look them up.
alter table feed.quotes add column if not exists balance0 double precision;
alter table feed.quotes add column if not exists balance1 double precision;
alter table feed.quotes add column if not exists ref_mid double precision;
-- The data API pages a pair's quotes by time: this finds the page's first row in one seek.
create index if not exists quotes_pair_ts on feed.quotes (prop_amm, lane, ts, block_number);

-- Every configuration the updater has run, as the file's JSON with its secrets redacted
-- (builder keys, a custom stanza's credentials, URLs cut to their host): a row at startup
-- and after every applied reload, kept when the updater saw the file change or, failing
-- that, when it differs from the newest row. A change only inside a redacted value is a
-- row identical to the one before it. So the newest row is the running config, and its
-- `ts` is when that config last changed; the row before it is what ran before. `source`
-- is `startup` or `reload`.
create table if not exists feed.config_changes (
  id bigserial primary key,
  ts bigint not null,
  source text not null,
  config jsonb not null
);

-- Every pair any recorded config has run, one row each, kept current as each config row is
-- written (`feed.apply_config`, called by the updater's insert), so the data API looks a pair
-- up with one seek instead of replaying the whole config history on every request. A pair
-- is its contract and its two tokens, sorted; `base`/`quote` are the order the newest
-- stanza declares, `stanza` that stanza, `ord` its position in that config. `active` is
-- "in the newest config row". `config_changed_at` is when the stanza became what it is: the
-- `ts` of the first row of the unbroken run of rows that held this exact stanza, so a pair
-- dropped and re-added starts a new run, and the updater moves it too, in the transaction
-- that adds the row, for a stanza that changed only inside a redacted value.
-- `last_config_id` is the newest row that had it.
create table if not exists feed.pairs (
  prop_amm text not null check (prop_amm = lower(prop_amm)),
  token0 text not null check (token0 = lower(token0)),
  token1 text not null check (token1 = lower(token1)),
  base text not null check (base = lower(base)),
  quote text not null check (quote = lower(quote)),
  stanza jsonb not null,
  ord integer not null,
  active boolean not null,
  config_changed_at bigint not null,
  last_config_id bigint not null,
  primary key (prop_amm, token0, token1)
);
create index if not exists pairs_tokens on feed.pairs (token0, token1, last_config_id);
create index if not exists pairs_base_quote on feed.pairs (base, quote, last_config_id);

-- Applies one `feed.config_changes` row to `feed.pairs`. Called with the row's values rather
-- than its id because the updater calls it from the statement that inserts the row, which
-- cannot read that row back. Rows must be applied in id order: the run rule compares against
-- the row before this one.
create or replace function feed.apply_config(cfg_id bigint, cfg_ts bigint, cfg jsonb) returns void
language plpgsql as $$
declare
  prev bigint;
begin
  select max(c.id) into prev from feed.config_changes c where c.id < cfg_id;
  update feed.pairs set active = false where active;
  insert into feed.pairs as p (prop_amm, token0, token1, base, quote, stanza, ord, active, config_changed_at, last_config_id)
  -- One row per pair even if a config lists it twice (the first wins, as the API always
  -- did), or the insert would touch one row twice and fail.
  select distinct on (t0, t1) lower(cfg->>'target'), t0, t1, b, q, s, ord::integer, true, cfg_ts, cfg_id
  from (
    select s, ord, lower(s->'tokens'->>0) as b, lower(s->'tokens'->>1) as q,
      least(lower(s->'tokens'->>0), lower(s->'tokens'->>1)) as t0,
      greatest(lower(s->'tokens'->>0), lower(s->'tokens'->>1)) as t1
    from jsonb_array_elements(coalesce(cfg->'pairs', '[]'::jsonb)) with ordinality as e(s, ord)
    where jsonb_typeof(s->'tokens') = 'array'
  ) stanzas
  order by t0, t1, ord
  on conflict (prop_amm, token0, token1) do update set
    base = excluded.base, quote = excluded.quote, ord = excluded.ord, active = true,
    config_changed_at = case when p.stanza = excluded.stanza and p.last_config_id = prev
      then p.config_changed_at else excluded.config_changed_at end,
    stanza = excluded.stanza, last_config_id = excluded.last_config_id;
end $$;

-- Built once from the history already recorded, the first time this file runs with the
-- table empty; from then on every insert keeps it current.
do $$
declare r record;
begin
  if not exists (select from feed.pairs) then
    for r in select id, ts, config from feed.config_changes order by id loop
      perform feed.apply_config(r.id, r.ts, r.config);
    end loop;
  end if;
end $$;

-- Grafana reads through the `grafana` role the host setup created with SELECT on `public`
-- only (deploy/ansible/setup-indexer-host.yml). Give it the same on `feed`, for these tables
-- and any added later. Skipped on a local database without that role.
do $$ begin
  if exists (select from pg_roles where rolname = 'grafana') then
    grant usage on schema feed to grafana;
    grant select on all tables in schema feed to grafana;
    alter default privileges in schema feed grant select on tables to grafana;
    grant execute on all functions in schema feed to grafana;
    alter default privileges in schema feed grant execute on functions to grafana;
  end if;
end $$;

-- Every fill our pools made, marked against the Binance mid at its second: the one query the
-- P&L panels share, so the dashboard's six panels are each a few lines over this instead of
-- six copies of it. A function rather than a view because it reads Ponder's views in
-- `public`, which every indexer deploy drops and recreates; a view here would either block
-- that drop or be cascaded away by it, while a function body is checked when the function
-- is created (turned off at the top of this file) and otherwise only resolved when called.
--
-- One row per swap. `q` is the signed base amount (positive when the vault received base),
-- `price` the fill price in quote per base, `mid` the Binance mid at or within 120 s before
-- the fill (null when the recorder has no row there), `vault` the pair's current vault from
-- `public.pairs`. Lane hashes and token addresses are our two pairs; a third pair is a third
-- row in the VALUES list. Addresses from `public` are lowercased before every comparison.
--
-- Dropped before it is created, not `create or replace`: replacing cannot change a
-- function's return columns, so the day one is added the whole file fails and, since the
-- updater runs it on every connect, the recorder stops writing until someone intervenes.
-- That happened when `published_mid` was added. Dropping first makes the file able to
-- apply any shape of this function, which is what "runs on every connect" requires. A
-- view depending on it would block the drop, which is why nothing here defines one.
-- Lookups for the dashboard, so no panel carries its own list of tokens or pairs.
--
-- A token's name in an exchange market: a wrapped token trades as its underlying, the same
-- rule as the updater's `unwrap_alias` (quote-updater/src/venues/mod.rs).
create or replace function feed.market_name(sym text) returns text
language sql immutable as $$
  select case upper(sym) when 'WETH' then 'ETH' when 'WBTC' then 'BTC' when 'CBBTC' then 'BTC'
    else upper(sym) end
$$;

-- Whether a token is a dollar, counted at 1 USD. The updater's list (`DOLLARS`, discover.rs).
create or replace function feed.is_dollar(sym text) returns boolean
language sql immutable as $$
  select upper(sym) in ('USDC', 'USDT', 'USD', 'FDUSD', 'DAI', 'USDE', 'PYUSD')
$$;

-- A token address's symbol, or the start of the address for one `feed.tokens` does not have.
create or replace function feed.token_symbol(tok text) returns text
language sql stable as $$
  select coalesce((select t.symbol from feed.tokens t where t.address = lower(tok)), left(tok, 10))
$$;

-- A raw amount of a token in whole tokens, or null if its decimals are not known.
create or replace function feed.token_amount(tok text, raw numeric) returns double precision
language sql stable as $$
  select (raw / 10 ^ t.decimals)::double precision from feed.tokens t where t.address = lower(tok)
$$;

-- A raw amount in USD when the token is a dollar, otherwise null.
create or replace function feed.dollar_amount(tok text, raw numeric) returns double precision
language sql stable as $$
  select (raw / 10 ^ t.decimals)::double precision from feed.tokens t
  where t.address = lower(tok) and feed.is_dollar(t.symbol)
$$;

-- A lane's name: the updater's label for it (from the newest quote it recorded on the lane),
-- or its two tokens' symbols in address order for a lane the updater never quoted.
create or replace function feed.pair_label(lane numeric, token0 text, token1 text) returns text
language sql stable as $$
  select coalesce(
    (select fq.label from feed.quotes fq where fq.lane = pair_label.lane order by fq.ts desc limit 1),
    feed.token_symbol(token0) || '/' || feed.token_symbol(token1))
$$;

-- Bounded by the window the caller asks for, matched against `block_timestamp` as Ponder
-- stores it (a numeric, bounds cast instead of the column) so the swaps are one range read
-- of Ponder's `(block_timestamp)` index. Unbounded, every panel marked every fill ever and
-- only then threw away the ones outside its window. The defaults keep a caller that passes
-- nothing (a dashboard older than this) working, as it did before.
drop function if exists feed.marked_fills();
drop function if exists feed.marked_fills(bigint, bigint);
create function feed.marked_fills(from_ts bigint default 0, to_ts bigint default 9223372036854775807)
returns table (
  block_number bigint,
  ts bigint,
  log_index integer,
  prop_amm text,
  label text,
  symbol text,
  base text,
  quote text,
  base_dec integer,
  q double precision,
  quote_amt double precision,
  price double precision,
  mid double precision,
  published_mid double precision,
  vault text
)
language sql stable as $$
  -- Every pair the indexer knows (`public.pairs`), named and scaled from `feed.tokens`.
  -- Its name is the updater's label for the lane (from the newest quote it recorded there),
  -- whose first half is the declared base; a pair the updater never quoted is named by its
  -- tokens in address order, base first. Its market is the base's Binance market in the
  -- quote as the updater records it (`ETHUSDC`), which the backfill also fills for history.
  with named as (
    select pk.pair_key::text as pair_key, t0.symbol as s0, t1.symbol as s1,
      t0.address as a0, t1.address as a1, t0.decimals as d0, t1.decimals as d1,
      coalesce(
        (select fq.label from feed.quotes fq where fq.lane = pk.pair_key order by fq.ts desc limit 1),
        t0.symbol || '/' || t1.symbol
      ) as label
    from (select distinct pair_key, lower(token0) as token0, lower(token1) as token1 from public.pairs) pk
    join feed.tokens t0 on t0.address = pk.token0
    join feed.tokens t1 on t1.address = pk.token1
  ),
  pairs as (
    select pair_key, label,
      case when split_part(label, '/', 1) = s1 then a1 else a0 end as base,
      case when split_part(label, '/', 1) = s1 then d1 else d0 end as base_dec,
      case when split_part(label, '/', 1) = s1 then a0 else a1 end as quote,
      case when split_part(label, '/', 1) = s1 then d0 else d1 end as quote_dec,
      case when split_part(label, '/', 1) = s1
        then feed.market_name(s1) || feed.market_name(s0)
        else feed.market_name(s0) || feed.market_name(s1) end as symbol
    from named
  ),
  -- Ponder stores chain integers as numeric(78). Cast to bigint here, once, because a
  -- numeric compared against feed.mids.ts (bigint) makes Postgres cast the indexed column
  -- and scan the whole mids table for every fill: 675 fills took minutes instead of
  -- milliseconds, measured on the server before this cast existed.
  fills as (
    select s.block_number::bigint as block_number, s.block_timestamp::bigint as ts, s.log_index::integer as log_index, lower(s.prop_amm) as prop_amm,
      p.pair_key, p.label, p.symbol, p.base, p.quote, p.base_dec,
      (case when lower(s.token_in) = p.base then s.amount_in else -s.amount_out end) / 10 ^ p.base_dec as q,
      (case when lower(s.token_in) = p.base then s.amount_out else s.amount_in end) / 10 ^ p.quote_dec as quote_amt
    from public.swaps s join pairs p on s.pair_key::text = p.pair_key
    where s.block_timestamp between from_ts::numeric and to_ts::numeric
  )
  select f.block_number, f.ts, f.log_index, f.prop_amm, f.label, f.symbol, f.base, f.quote, f.base_dec,
    f.q, f.quote_amt, f.quote_amt / abs(f.q) as price,
    (select m.mid from feed.mids m where m.symbol = f.symbol and m.ts between f.ts - 120 and f.ts order by m.ts desc limit 1) as mid,
    -- The mid the contract priced this fill from: the update that landed on this lane in
    -- the fill's own block. `public.price_updates` is what actually reached the chain,
    -- which is what a fill is priced against, and it goes back to the first block we ever
    -- quoted, so the spread split covers all of history rather than only the days since
    -- the updater started recording its own quotes in `feed.quotes`.
    --
    -- The fill's own block, not "the newest at or before it": the registry's freshness
    -- window is zero width, so an update is only usable in the block it is stamped for.
    -- That makes this one index seek per fill on (target, block_number) rather than a walk
    -- back through the lane's history, and a fill with no update in its block reports null
    -- rather than being marked against a price that was never in force. `target` is
    -- compared as stored, since Ponder lowercases addresses and `lower()` here would only
    -- defeat that index: with it, this lookup was over a second per panel on a database
    -- loaded to production size, and without it the same panels are tens of milliseconds.
    --
    -- Turned the same way up as `price` and `mid`, which are quote per base as this
    -- function's `base` column declares it. The chain carries the mid in **lane**
    -- orientation and scaled by 1e18, so a pair whose declared base sorts second
    -- (USDC/WETH: WETH is the base and sorts above USDC) holds the reciprocal there.
    -- Without this the subtraction would mix 2600 with 0.00038.
    (select case when f.base > f.quote then 1e18 / nullif(u.mid, 0) else u.mid / 1e18 end
       from public.price_updates u
       where u.target = f.prop_amm and u.block_number = f.block_number
         and u.lane = f.pair_key::numeric and u.success and u.mid > 0
       limit 1) as published_mid,
    -- Compared as stored (Ponder lowercases addresses), so this is one seek on the
    -- primary key of `pairs`; `lower()` on the columns would read the whole table per fill.
    (select lower(pr.vault) from public.pairs pr where pr.prop_amm = f.prop_amm and pr.token0 = least(f.base, f.quote) and pr.token1 = greatest(f.base, f.quote)) as vault
  from fills f
$$;

-- Every price update we landed, with its gas in USD (at the Binance ETH mid of its second):
-- the cost side of "spread P&L minus gas".
--
-- Bounded by the window the caller asks for, and the ETH mid read once per second an
-- update landed in rather than once per update. Both lanes publish in the same block, so
-- a window's updates carry half as many distinct seconds as rows, and every one of those
-- reads is an index seek into a table with a row per second: unbounded and undeduplicated
-- that was 288k seeks over three weeks and most of the P&L panels' time, measured on a
-- database loaded to production size. Each update still takes the mid of its own second,
-- so every row is the value it was before.
--
-- The window is matched against `block_timestamp` as Ponder stores it, a numeric, with the
-- bounds cast instead of the column, and the join to the priced second is on that same
-- numeric. Casting the column hid its statistics: Postgres estimated eleven updates in the
-- window instead of the real seventeen hundred, chose a nested loop over a hash join for
-- that last join, and compared 1.5 million pairs of rows to find seventeen hundred matches.
-- That was 240 ms of the 270 ms panel 40 took, measured on the production database.
--
-- Dropped first for the same reason as `marked_fills` above, and by both signatures, so a
-- database still holding the parameterless one ends up with this and not with both.
drop function if exists feed.update_gas();
drop function if exists feed.update_gas(bigint, bigint);
create function feed.update_gas(from_ts bigint default 0, to_ts bigint default 9223372036854775807)
returns table (ts bigint, label text, usd double precision)
language sql stable as $$
  with secs as (
    select distinct u.block_timestamp as bt
    from public.price_updates u
    where u.block_timestamp between from_ts::numeric and to_ts::numeric
  ),
  -- Each lane's name, looked up once per lane: the updater's label, from the newest quote
  -- it recorded on the lane.
  names as (
    select l.lane,
      (select fq.label from feed.quotes fq where fq.lane = l.lane order by fq.ts desc limit 1) as label
    from (select distinct lane from public.price_updates
          where block_timestamp between from_ts::numeric and to_ts::numeric) l
  ),
  priced as (
    select secs.bt,
      (select m.mid from feed.mids m
        where m.symbol = 'ETHUSDC'
          and m.ts between secs.bt::bigint - 120 and secs.bt::bigint
        order by m.ts desc limit 1) as mid
    from secs
  )
  select u.block_timestamp::bigint as ts,
    coalesce(n.label, left(u.lane::text, 8)) as label,
    (t.gas_used * t.effective_gas_price / 1e18)::double precision * p.mid as usd
  from public.price_updates u
  join public.transactions t on t.hash = u.tx_hash
  left join priced p on p.bt = u.block_timestamp
  left join names n on n.lane = u.lane
  where u.block_timestamp between from_ts::numeric and to_ts::numeric
$$;
