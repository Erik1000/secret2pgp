ALTER TABLE
    actions
ADD
    COLUMN created_at timestamptz NOT NULL DEFAULT now();