CREATE TABLE IF NOT EXISTS universe_roots (
    id INTEGER PRIMARY KEY,

    -- For the namespace root, we set the foreign key constraint evaluation to
    -- be deferred until after the database transaction ends. Otherwise, if the
    -- root of the SMT is deleted temporarily before inserting a new root, then
    -- this constraint is violated as there's no longer a root that this
    -- universe tree can point to.
    namespace_root VARCHAR UNIQUE NOT NULL REFERENCES mssmt_roots(namespace) DEFERRABLE INITIALLY DEFERRED,

    asset_id BLOB,

    -- We use the 32 byte schnorr key here as this is what's used to derive the
    -- top-level Taro commitment key.
    group_key BLOB CHECK(LENGTH(group_key) = 32)
);

CREATE INDEX IF NOT EXISTS universe_roots_asset_id_idx ON universe_roots(asset_id);
CREATE INDEX IF NOT EXISTS universe_roots_group_key_idx ON universe_roots(group_key);

CREATE TABLE IF NOT EXISTS universe_leaves (
    id INTEGER PRIMARY KEY,

    asset_genesis_id INTEGER NOT NULL REFERENCES genesis_assets(gen_asset_id),

    minting_point BLOB NOT NULL, 

    script_key_bytes BLOB NOT NULL CHECK(LENGTH(script_key_bytes) = 32),

    universe_root_id INTEGER NOT NULL REFERENCES universe_roots(id),

    leaf_node_key BLOB,
    
    leaf_node_namespace VARCHAR NOT NULL,

    UNIQUE(minting_point, script_key_bytes)
);

CREATE INDEX IF NOT EXISTS universe_leaves_key_idx ON universe_leaves(leaf_node_key);
CREATE INDEX IF NOT EXISTS universe_leaves_namespace ON universe_leaves(leaf_node_namespace);

CREATE TABLE IF NOT EXISTS universe_servers (
    id INTEGER PRIMARY KEY,

    server_host TEXT UNIQUE NOT NULL,

    -- TODO(roasbeef): do host + port? then unique on that?

    last_sync_time TIMESTAMP NOT NULL

    -- TODO(roasbeef): can also add stuff like filters re which items to sync,
    -- etc? also sync mode, ones that should get everything pushed, etc
);

CREATE INDEX IF NOT EXISTS universe_servers_host ON universe_servers(server_host);

CREATE TABLE IF NOT EXISTS universe_events (
    event_id INTEGER PRIMARY KEY,

    event_type VARCHAR NOT NULL CHECK (event_type IN ('SYNC', 'NEW_PROOF', 'NEW_ROOT')),

    universe_root_id INTEGER NOT NULL REFERENCES universe_roots(id),

    -- TODO(roasbeef): also add which leaf was synced?

    event_time TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS universe_events_event_time_idx ON universe_events(event_time);
CREATE INDEX IF NOT EXISTS universe_events_type_idx ON universe_events(event_type);

-- universe_stats is a view that gives us easy access to the total number of
-- syncs and proofs for a given asset.
CREATE VIEW universe_stats AS
    SELECT
        COUNT(CASE WHEN u.event_type = 'SYNC' THEN 1 ELSE NULL END) AS total_asset_syncs,
        COUNT(CASE WHEN u.event_type = 'NEW_PROOF' THEN 1 ELSE NULL END) AS total_asset_proofs,
        roots.asset_id,
        roots.group_key,
        roots.namespace_root
    FROM universe_events u
    JOIN universe_roots roots ON u.universe_root_id = roots.id
    GROUP BY roots.asset_id, roots.group_key, roots.namespace_root;
