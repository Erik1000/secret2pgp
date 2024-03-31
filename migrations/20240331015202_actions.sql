CREATE TABLE actions (
    "action_id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "requirements" jsonb NOT NULL DEFAULT '[]',
    "action" jsonb NOT NULL
);

-- maps tags to actions
CREATE TABLE active_actions (
    "tag_uid" tag_uid NOT NULL REFERENCES tags("uid"),
    "action_id" uuid NOT NULL REFERENCES actions("action_id"),
    PRIMARY KEY ("tag_uid", "action_id")
);