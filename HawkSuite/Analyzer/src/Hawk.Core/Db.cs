using Microsoft.Data.Sqlite;

namespace Hawk.Core;

/// <summary>Session database — one hawk.db per imported .hawk session.</summary>
public static class Db
{
    public static SqliteConnection Open(string dbPath)
    {
        var conn = new SqliteConnection($"Data Source={dbPath}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = Schema;
        cmd.ExecuteNonQuery();
        return conn;
    }

    // Modeled on Redline's AuditDataSchema concept: one table per artifact
    // type + session metadata + analyst state (scores, tags) kept separate
    // from raw observations.
    private const string Schema = """
        CREATE TABLE IF NOT EXISTS session (
            key TEXT PRIMARY KEY, value TEXT
        );
        CREATE TABLE IF NOT EXISTS processes (
            id INTEGER PRIMARY KEY,
            pid INTEGER, ppid INTEGER, name TEXT, path TEXT,
            command_line TEXT, user TEXT, session_id INTEGER,
            start_time_utc TEXT,
            sha256 TEXT, md5 TEXT, signature_status TEXT, signer TEXT,
            parent_name TEXT, parent_path TEXT
        );
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY,
            name TEXT, display_name TEXT, state TEXT, start_mode TEXT, account TEXT,
            path_name TEXT, binary_path TEXT,
            sha256 TEXT, md5 TEXT, signature_status TEXT, signer TEXT,
            service_dll TEXT, service_dll_md5 TEXT, service_dll_sha256 TEXT,
            service_dll_signer TEXT, service_dll_sig_status TEXT,
            service_type TEXT, description TEXT, process_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS scheduled_tasks (
            id INTEGER PRIMARY KEY,
            task_name TEXT, task_path TEXT, state TEXT, author TEXT,
            run_as TEXT, run_level TEXT, execute TEXT, arguments TEXT,
            working_directory TEXT, binary_path TEXT,
            sha256 TEXT, md5 TEXT, signature_status TEXT, signer TEXT,
            last_run_time_utc TEXT, next_run_time_utc TEXT,
            last_task_result TEXT, triggers TEXT
        );
        CREATE TABLE IF NOT EXISTS registry_runkeys (
            id INTEGER PRIMARY KEY,
            key_path TEXT, user_sid TEXT, value_name TEXT, command TEXT,
            binary_path TEXT, sha256 TEXT, md5 TEXT, signature_status TEXT, signer TEXT
        );
        CREATE TABLE IF NOT EXISTS startup_folder (
            id INTEGER PRIMARY KEY,
            user TEXT, item_path TEXT, item_name TEXT, target TEXT, target_arguments TEXT,
            sha256 TEXT, md5 TEXT, signature_status TEXT, signer TEXT,
            created_utc TEXT, modified_utc TEXT
        );
        CREATE TABLE IF NOT EXISTS wmi_persistence (
            id INTEGER PRIMARY KEY,
            object_type TEXT, name TEXT, query TEXT, query_language TEXT,
            event_namespace TEXT, consumer_type TEXT, destination TEXT,
            filter_ref TEXT, consumer_ref TEXT
        );
        CREATE TABLE IF NOT EXISTS network_connections (
            id INTEGER PRIMARY KEY,
            protocol TEXT, local_address TEXT, local_port INTEGER,
            remote_address TEXT, remote_port INTEGER, state TEXT,
            pid INTEGER, process_name TEXT, process_path TEXT, creation_time_utc TEXT
        );
        CREATE TABLE IF NOT EXISTS artifact_records (
            -- catch-all for artifact types without a typed table (dns_cache,
            -- arp_entries, named_pipes, local_users, logon_sessions, ...)
            id INTEGER PRIMARY KEY,
            artifact_type TEXT NOT NULL,
            record_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_generic_type ON artifact_records(artifact_type);
        CREATE INDEX IF NOT EXISTS idx_svc_md5  ON services(md5);
        CREATE INDEX IF NOT EXISTS idx_task_md5 ON scheduled_tasks(md5);
        CREATE INDEX IF NOT EXISTS idx_net_pid  ON network_connections(pid);
        CREATE TABLE IF NOT EXISTS mri_scores (
            -- analyst-side state: NEVER comes from the collector
            artifact_table TEXT NOT NULL,
            artifact_id INTEGER NOT NULL,
            score INTEGER NOT NULL,
            band TEXT NOT NULL,            -- trusted|low|medium|high|critical
            trust_verdict TEXT NOT NULL,   -- TRUSTED|NEUTRAL|SCORED|MALICIOUS
            matched_rules TEXT,            -- JSON array of rule ids w/ points
            PRIMARY KEY (artifact_table, artifact_id)
        );
        CREATE TABLE IF NOT EXISTS tags (
            artifact_table TEXT NOT NULL,
            artifact_id INTEGER NOT NULL,
            tag TEXT NOT NULL,             -- benign|suspicious|confirmed
            note TEXT,
            tagged_at_utc TEXT,
            PRIMARY KEY (artifact_table, artifact_id)
        );
        CREATE TABLE IF NOT EXISTS timeline (
            id INTEGER PRIMARY KEY,
            ts_utc TEXT,                   -- NULL = unknown, displayed as [UNKNOWN]
            source TEXT, category TEXT,
            summary TEXT, detail TEXT,
            artifact_table TEXT, artifact_id INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_timeline_ts ON timeline(ts_utc);
        CREATE INDEX IF NOT EXISTS idx_proc_md5 ON processes(md5);

        -- ===== raw-parser output (populated at import by Hawk.Parsers) =====
        CREATE TABLE IF NOT EXISTS event_logs (
            id INTEGER PRIMARY KEY,
            ts_utc TEXT, channel TEXT, provider TEXT, event_id INTEGER,
            level TEXT, computer TEXT, user_sid TEXT,
            summary TEXT,                  -- short label + key fields
            event_data TEXT                -- JSON object of EventData fields
        );
        CREATE INDEX IF NOT EXISTS idx_evt_id ON event_logs(event_id);
        CREATE INDEX IF NOT EXISTS idx_evt_ts ON event_logs(ts_utc);
        CREATE INDEX IF NOT EXISTS idx_evt_chan ON event_logs(channel);
        CREATE TABLE IF NOT EXISTS prefetch (
            id INTEGER PRIMARY KEY,
            file_name TEXT, executable TEXT, prefetch_hash TEXT,
            run_count INTEGER, last_run_utc TEXT,
            run_times TEXT,                -- JSON array, up to 8 ISO timestamps
            referenced_files TEXT,         -- JSON array of loaded files/DLLs
            volume_serial TEXT, volume_created_utc TEXT,
            format_version INTEGER
        );
        CREATE TABLE IF NOT EXISTS shimcache (
            -- NOTE: on Win8+ shimcache proves PRESENCE, not execution; the
            -- timestamp is the file's $SI mtime, NOT an execution time. It is
            -- therefore deliberately NOT fed into the timeline.
            id INTEGER PRIMARY KEY,
            entry_position INTEGER,        -- insertion order (most recent first)
            path TEXT, last_modified_utc TEXT,
            executed INTEGER,              -- Win7 InsertFlags only; NULL on Win8+
            control_set INTEGER
        );
        CREATE TABLE IF NOT EXISTS amcache (
            id INTEGER PRIMARY KEY,
            entry_type TEXT,               -- application_file | driver_binary
            path TEXT, name TEXT, publisher TEXT, version TEXT,
            sha1 TEXT, size INTEGER,
            link_date_utc TEXT,            -- PE compile time, not host activity
            key_last_written_utc TEXT,
            binary_type TEXT, product_name TEXT,
            driver_signed INTEGER, driver_company TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_amcache_sha1 ON amcache(sha1);
        CREATE TABLE IF NOT EXISTS mft_entries (
            id INTEGER PRIMARY KEY,
            record_number INTEGER, in_use INTEGER, is_directory INTEGER,
            file_name TEXT, full_path TEXT, parent_record INTEGER,
            si_created_utc TEXT, si_modified_utc TEXT, si_accessed_utc TEXT,
            fn_created_utc TEXT, logical_size INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_mft_path ON mft_entries(full_path);
        CREATE INDEX IF NOT EXISTS idx_mft_name ON mft_entries(file_name);
        CREATE INDEX IF NOT EXISTS idx_mft_inuse ON mft_entries(in_use);
        CREATE TABLE IF NOT EXISTS usn_journal (
            id INTEGER PRIMARY KEY,
            ts_utc TEXT, usn INTEGER, file_ref INTEGER, parent_ref INTEGER,
            file_name TEXT, reasons TEXT, file_attributes INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_usn_ts ON usn_journal(ts_utc);
        CREATE INDEX IF NOT EXISTS idx_usn_name ON usn_journal(file_name);
        CREATE TABLE IF NOT EXISTS findings (
            -- aggregate detections that span multiple rows (e.g. password
            -- spray over hundreds of 4625s) or standalone event verdicts
            id INTEGER PRIMARY KEY,
            rule TEXT NOT NULL,
            severity TEXT NOT NULL,        -- low|medium|high|critical
            summary TEXT NOT NULL, detail TEXT,
            ts_utc TEXT,
            artifact_table TEXT, artifact_id INTEGER
        );
        """;
}
