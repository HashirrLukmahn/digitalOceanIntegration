CREATE TABLE `oauth_connection` (
	`id` text PRIMARY KEY NOT NULL,
	`access_token_ct` text NOT NULL,
	`refresh_token_ct` text,
	`expires_at` integer,
	`granted_scopes` text DEFAULT '' NOT NULL,
	`team_name` text,
	`team_uuid` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `oauth_states` (
	`state_hash` text PRIMARY KEY NOT NULL,
	`redirect_uri` text NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`consumed_at` integer
);
