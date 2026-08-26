CREATE TABLE `snapshots` (
	`id` text PRIMARY KEY NOT NULL,
	`account_id` text NOT NULL,
	`sync_run_id` text NOT NULL,
	`snapshot_version` text NOT NULL,
	`status` text NOT NULL,
	`document_json` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`account_id`) REFERENCES `cloud_accounts`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`sync_run_id`) REFERENCES `sync_runs`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `snapshots_account_created_idx` ON `snapshots` (`account_id`,`created_at`);