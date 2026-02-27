package db

import (
	"context"
	"database/sql"
	"fmt"
)

var migrations = []string{
	`create extension if not exists pgcrypto;`,
	`create table if not exists schema_migrations (version int primary key);`,
	`do $$ begin if not exists (select 1 from schema_migrations where version = 1) then
		create table users (
			id uuid primary key,
			email text not null unique,
			password_hash text not null,
			role text not null,
			created_at timestamptz not null default now()
		);
		create table sessions (
			id uuid primary key,
			user_id uuid not null references users(id) on delete cascade,
			expires_at timestamptz not null,
			created_at timestamptz not null default now()
		);
		create index if not exists sessions_user_id_idx on sessions(user_id);
		create table enroll_tokens (
			id uuid primary key,
			token_hash bytea not null unique,
			expires_at timestamptz not null,
			used_at timestamptz,
			created_at timestamptz not null default now()
		);
		create table nodes (
			id uuid primary key,
			name text not null,
			agent_host text not null,
			agent_port int not null,
			server_cert_cn text not null,
			created_at timestamptz not null default now(),
			last_seen_at timestamptz
		);
		create table audit_log (
			id uuid primary key,
			user_id uuid references users(id) on delete set null,
			action text not null,
			meta jsonb not null default '{}'::jsonb,
			created_at timestamptz not null default now()
		);
		insert into schema_migrations (version) values (1);
	end if; end $$;`,
	`do $$ begin if not exists (select 1 from schema_migrations where version = 2) then
		create table settings (
			key text primary key,
			value text not null
		);
		insert into schema_migrations (version) values (2);
	end if; end $$;`,
}

func Migrate(ctx context.Context, db *sql.DB) error {
	for i, m := range migrations {
		if _, err := db.ExecContext(ctx, m); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
	}
	return nil
}
