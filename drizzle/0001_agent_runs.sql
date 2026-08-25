CREATE TABLE `agent_runs` (
	`id` text PRIMARY KEY NOT NULL,
	`account_id` text NOT NULL,
	`outcome` text NOT NULL,
	`steps` integer DEFAULT 0 NOT NULL,
	`tool_calls_json` text DEFAULT '[]' NOT NULL,
	`findings_json` text DEFAULT '[]' NOT NULL,
	`error` text,
	`started_at` integer NOT NULL,
	`completed_at` integer,
	FOREIGN KEY (`account_id`) REFERENCES `cloud_accounts`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `agent_runs_account_started_idx` ON `agent_runs` (`account_id`,`started_at`);