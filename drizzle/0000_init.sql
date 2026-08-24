CREATE TABLE `cloud_accounts` (
	`id` text PRIMARY KEY NOT NULL,
	`provider` text DEFAULT 'digitalocean' NOT NULL,
	`external_id` text NOT NULL,
	`name` text NOT NULL,
	`last_synced_at` integer,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `cloud_accounts_provider_external_idx` ON `cloud_accounts` (`provider`,`external_id`);--> statement-breakpoint
CREATE TABLE `cloud_relationships` (
	`id` text PRIMARY KEY NOT NULL,
	`account_id` text NOT NULL,
	`source_external_id` text NOT NULL,
	`target_external_id` text NOT NULL,
	`relationship` text NOT NULL,
	`evidence` text NOT NULL,
	`metadata_json` text DEFAULT '{}' NOT NULL,
	FOREIGN KEY (`account_id`) REFERENCES `cloud_accounts`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `cloud_relationships_unique_idx` ON `cloud_relationships` (`account_id`,`source_external_id`,`target_external_id`,`relationship`);--> statement-breakpoint
CREATE INDEX `cloud_relationships_source_idx` ON `cloud_relationships` (`account_id`,`source_external_id`);--> statement-breakpoint
CREATE INDEX `cloud_relationships_target_idx` ON `cloud_relationships` (`account_id`,`target_external_id`);--> statement-breakpoint
CREATE TABLE `cloud_resources` (
	`id` text PRIMARY KEY NOT NULL,
	`account_id` text NOT NULL,
	`external_id` text NOT NULL,
	`resource_type` text NOT NULL,
	`name` text NOT NULL,
	`region` text,
	`state` text,
	`is_internet_exposed` integer DEFAULT false NOT NULL,
	`sensitivity` text DEFAULT 'none' NOT NULL,
	`tags_json` text DEFAULT '{}' NOT NULL,
	`metadata_json` text DEFAULT '{}' NOT NULL,
	`first_seen_at` integer NOT NULL,
	`last_seen_at` integer NOT NULL,
	`removed_at` integer,
	FOREIGN KEY (`account_id`) REFERENCES `cloud_accounts`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `cloud_resources_account_external_idx` ON `cloud_resources` (`account_id`,`external_id`);--> statement-breakpoint
CREATE INDEX `cloud_resources_type_idx` ON `cloud_resources` (`account_id`,`resource_type`);--> statement-breakpoint
CREATE INDEX `cloud_resources_exposed_idx` ON `cloud_resources` (`account_id`,`is_internet_exposed`);--> statement-breakpoint
CREATE TABLE `exposure_findings` (
	`id` text PRIMARY KEY NOT NULL,
	`account_id` text NOT NULL,
	`resource_external_id` text NOT NULL,
	`kind` text NOT NULL,
	`severity` text NOT NULL,
	`title` text NOT NULL,
	`summary` text NOT NULL,
	`evidence_json` text DEFAULT '{}' NOT NULL,
	`remediation` text NOT NULL,
	`first_seen_at` integer NOT NULL,
	`last_seen_at` integer NOT NULL,
	`resolved_at` integer,
	FOREIGN KEY (`account_id`) REFERENCES `cloud_accounts`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `exposure_findings_account_severity_idx` ON `exposure_findings` (`account_id`,`severity`);--> statement-breakpoint
CREATE INDEX `exposure_findings_resource_idx` ON `exposure_findings` (`account_id`,`resource_external_id`);--> statement-breakpoint
CREATE TABLE `sync_runs` (
	`id` text PRIMARY KEY NOT NULL,
	`account_id` text NOT NULL,
	`status` text NOT NULL,
	`resources_count` integer DEFAULT 0 NOT NULL,
	`relationships_count` integer DEFAULT 0 NOT NULL,
	`findings_count` integer DEFAULT 0 NOT NULL,
	`coverage_json` text DEFAULT '{"completedCollectors":[],"failedCollectors":[],"unavailableCollectors":[]}' NOT NULL,
	`error` text,
	`started_at` integer NOT NULL,
	`completed_at` integer,
	FOREIGN KEY (`account_id`) REFERENCES `cloud_accounts`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `sync_runs_account_started_idx` ON `sync_runs` (`account_id`,`started_at`);