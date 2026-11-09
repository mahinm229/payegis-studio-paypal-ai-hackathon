/**
 * Payegis Studio v3.5 — Durable Checkpoint Store, Append-Only Operation Journal,
 * PostgreSQL Distributed Advisory Locking & Optimistic Version Control
 * Canonical Module: `./persistence-store.mjs`
 *
 * Implements Phase 6 & Finding #5 Fixes:
 * - True PostgreSQL distributed advisory locks (`pg_try_advisory_lock($1, $2)` / `pg_advisory_unlock($1, $2)` and `pg_advisory_xact_lock`)
 *   derived deterministically from `SHA-256(sessionId)` via `computePostgresAdvisoryLockPair(sessionId)`.
 * - Cross-process atomic OS kernel lockfiles (`fs.openSync(lockFile, 'wx')`) for local multi-process concurrency protection.
 * - Optimistic version control (`session.version` incremented on every save; rejects stale version overwrites with HTTP 409 `STALE_SESSION_VERSION_CONFLICT`).
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.join(__dirname, '.payegis-data');

const sessionLocks = new Map();

/**
 * Computes two deterministic 32-bit signed integers from `sessionId`
 * for PostgreSQL `pg_try_advisory_lock(int4, int4)` / `pg_advisory_xact_lock(int4, int4)`.
 */
export function computePostgresAdvisoryLockPair(sessionId) {
  const digest = crypto
    .createHash('sha256')
    .update(String(sessionId || 'DEFAULT_SESSION'), 'utf8')
    .digest();
  return [digest.readInt32BE(0), digest.readInt32BE(4)];
}

export async function withSessionLock(sessionId, fn, storeInstance = null) {
  if (storeInstance && typeof storeInstance.withDistributedSessionLock === 'function') {
    return storeInstance.withDistributedSessionLock(sessionId, fn);
  }
  const key = sessionId || 'DEFAULT_SESSION';
  if (sessionLocks.get(key)) {
    const err = new Error(
      `CONCURRENT_OPERATION_IN_PROGRESS: Another financial mutation is currently executing on session ${key}.`
    );
    err.statusCode = 409;
    err.code = 'CONCURRENT_OPERATION_IN_PROGRESS';
    throw err;
  }
  sessionLocks.set(key, true);
  try {
    return await fn();
  } finally {
    sessionLocks.delete(key);
  }
}

export class DurableCheckpointStore {
  constructor(options = {}) {
    this.pgPool = options.pgPool || null;
    this.backendType = this.pgPool
      ? 'POSTGRESQL_DURABLE_DB'
      : 'ATOMIC_DISK_SNAPSHOT_AND_JSONL_JOURNAL';
    this.initialized = Boolean(this.pgPool);
    this.dataDir = options.dataDir || DATA_DIR;
    this.locksDir = path.join(this.dataDir, 'locks');
    this.snapshotFile = path.join(this.dataDir, 'durable-sessions.json');
    this.journalFile = path.join(this.dataDir, 'operation-journal.jsonl');
  }

  async init() {
    if (this.initialized) return;
    const isProd = process.env.NODE_ENV === 'production';
    const dbUrl = (process.env.DATABASE_URL || '').trim();
    const hasConfiguredPostgres =
      Boolean(dbUrl) && !dbUrl.includes('localhost:5432/payegis_hitl_state');

    if (hasConfiguredPostgres) {
      try {
        const pg = await import('pg');
        const Pool = pg.default?.Pool || pg.Pool;
        this.pgPool = new Pool({ connectionString: dbUrl, connectionTimeoutMillis: 5000 });
        await this.pgPool.query(`
          CREATE TABLE IF NOT EXISTS payegis_escrow_checkpoints (
            session_id TEXT PRIMARY KEY,
            version INTEGER NOT NULL DEFAULT 1,
            state TEXT NOT NULL,
            payload JSONB NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
          );
          CREATE TABLE IF NOT EXISTS payegis_operation_journal (
            id BIGSERIAL PRIMARY KEY,
            session_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            phase TEXT NOT NULL,
            operation TEXT NOT NULL,
            details JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(session_id, request_id, phase)
          );
        `);
        this.backendType = 'POSTGRESQL_DURABLE_DB';
        this.initialized = true;
        return;
      } catch (pgErr) {
        this.pgPool = null;
        if (isProd) {
          const err = new Error(
            `PRODUCTION_DATABASE_INIT_FAILED: Cannot fall back to ephemeral disk in production (${pgErr.message}).`
          );
          err.statusCode = 503;
          err.code = 'PRODUCTION_DATABASE_INIT_FAILED';
          throw err;
        }
      }
    }

    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
    if (!fs.existsSync(this.locksDir)) {
      fs.mkdirSync(this.locksDir, { recursive: true });
    }
    if (!fs.existsSync(this.snapshotFile)) {
      fs.writeFileSync(
        this.snapshotFile,
        JSON.stringify({ sessions: {}, archivedSessions: [] }, null, 2),
        'utf8'
      );
    }
    if (!fs.existsSync(this.journalFile)) {
      fs.writeFileSync(this.journalFile, '', 'utf8');
    }
    this.backendType = 'ATOMIC_DISK_SNAPSHOT_AND_JSONL_JOURNAL';
    this.initialized = true;
  }

  /**
   * Finding #5 Fix:
   * Acquires both an in-process mutex AND a distributed lock:
   * - In PostgreSQL mode: checks out a client and executes `SELECT pg_try_advisory_lock($1, $2) AS acquired`,
   *   holding the PostgreSQL distributed advisory lock across the entire financial mutation and unlocking in `finally`.
   * - In disk mode: creates an exclusive OS lockfile (`fs.openSync(lockPath, 'wx')`) so multiple Node processes
   *   cannot concurrently mutate the same session.
   */
  async withDistributedSessionLock(sessionId, fn) {
    await this.init();
    const key = String(sessionId || 'DEFAULT_SESSION');
    if (sessionLocks.get(key)) {
      const err = new Error(
        `CONCURRENT_OPERATION_IN_PROGRESS: Another financial mutation is currently executing on session ${key}.`
      );
      err.statusCode = 409;
      err.code = 'CONCURRENT_OPERATION_IN_PROGRESS';
      throw err;
    }

    sessionLocks.set(key, true);
    let pgClient = null;
    let pgLocked = false;
    let lockFileDescriptor = null;
    const safeFileName = key.replace(/[^A-Za-z0-9_-]/g, '_');
    const lockFilePath = path.join(this.locksDir, `${safeFileName}.lock`);
    const [k1, k2] = computePostgresAdvisoryLockPair(key);

    try {
      if (this.pgPool) {
        pgClient = await this.pgPool.connect();
        const lockRes = await pgClient.query(
          'SELECT pg_try_advisory_lock($1, $2) AS acquired;',
          [k1, k2]
        );
        const acquired = Boolean(lockRes.rows?.[0]?.acquired);
        if (!acquired) {
          const err = new Error(
            `DISTRIBUTED_POSTGRES_LOCK_BUSY: Session ${key} is currently locked by another server instance.`
          );
          err.statusCode = 409;
          err.code = 'DISTRIBUTED_POSTGRES_LOCK_BUSY';
          throw err;
        }
        pgLocked = true;
      } else {
        if (!fs.existsSync(this.locksDir)) {
          fs.mkdirSync(this.locksDir, { recursive: true });
        }
        try {
          lockFileDescriptor = fs.openSync(lockFilePath, 'wx');
          fs.writeFileSync(
            lockFileDescriptor,
            JSON.stringify({ pid: process.pid, sessionId: key, acquiredAt: Date.now() }),
            'utf8'
          );
        } catch (fsErr) {
          if (fsErr.code === 'EEXIST') {
            // Check if lock is stale (>30 seconds old)
            try {
              const stat = fs.statSync(lockFilePath);
              if (Date.now() - stat.mtimeMs > 30000) {
                fs.unlinkSync(lockFilePath);
                lockFileDescriptor = fs.openSync(lockFilePath, 'wx');
              } else {
                const err = new Error(
                  `DISTRIBUTED_FILE_LOCK_BUSY: Session ${key} is locked by another process.`
                );
                err.statusCode = 409;
                err.code = 'DISTRIBUTED_FILE_LOCK_BUSY';
                throw err;
              }
            } catch (innerErr) {
              if (innerErr.code === 'DISTRIBUTED_FILE_LOCK_BUSY') throw innerErr;
            }
          } else {
            throw fsErr;
          }
        }
      }

      return await fn(pgClient);
    } finally {
      if (pgClient) {
        if (pgLocked) {
          try {
            await pgClient.query('SELECT pg_advisory_unlock($1, $2);', [k1, k2]);
          } catch (_) {}
        }
        try {
          pgClient.release();
        } catch (_) {}
      }
      if (lockFileDescriptor !== null) {
        try {
          fs.closeSync(lockFileDescriptor);
        } catch (_) {}
        try {
          if (fs.existsSync(lockFilePath)) fs.unlinkSync(lockFilePath);
        } catch (_) {}
      }
      sessionLocks.delete(key);
    }
  }

  async appendOperationJournal(entry) {
    await this.init();
    const record = {
      timestamp: new Date().toISOString(),
      sessionId: entry.sessionId,
      requestId: entry.requestId,
      phase: entry.phase || 'PRE_FLIGHT',
      operation: entry.operation,
      details: entry.details || {},
    };

    if (this.pgPool) {
      await this.pgPool.query(
        `INSERT INTO payegis_operation_journal (session_id, request_id, phase, operation, details)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (session_id, request_id, phase) DO NOTHING;`,
        [
          record.sessionId,
          record.requestId,
          record.phase,
          record.operation,
          JSON.stringify(record.details),
        ]
      );
      return record;
    }

    fs.appendFileSync(this.journalFile, JSON.stringify(record) + '\n', 'utf8');
    return record;
  }

  async readOperationJournal() {
    await this.init();
    if (this.pgPool) {
      const res = await this.pgPool.query(
        `SELECT session_id AS "sessionId", request_id AS "requestId", phase, operation, details, created_at AS timestamp
         FROM payegis_operation_journal ORDER BY id ASC;`
      );
      return res.rows;
    }
    if (!fs.existsSync(this.journalFile)) return [];
    const lines = fs
      .readFileSync(this.journalFile, 'utf8')
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
    return lines.map((line) => JSON.parse(line));
  }

  /**
   * Saves session with PostgreSQL transaction advisory lock + optimistic version control (`options.expectedVersion`).
   */
  async saveSession(session, options = {}) {
    await this.init();
    const incomingVersion = Number(session.version || 1);

    if (this.pgPool) {
      const [k1, k2] = computePostgresAdvisoryLockPair(session.sessionId);
      const client = await this.pgPool.connect();
      try {
        await client.query('BEGIN');
        await client.query('SELECT pg_advisory_xact_lock($1, $2);', [k1, k2]);
        const existing = await client.query(
          `SELECT version FROM payegis_escrow_checkpoints WHERE session_id = $1 FOR UPDATE;`,
          [session.sessionId]
        );
        if (existing.rows.length > 0) {
          const dbVersion = Number(existing.rows[0].version);
          if (options.expectedVersion !== undefined && options.expectedVersion !== dbVersion) {
            const err = new Error(
              `STALE_SESSION_VERSION_CONFLICT: Expected version ${options.expectedVersion}, found ${dbVersion}.`
            );
            err.statusCode = 409;
            err.code = 'STALE_SESSION_VERSION_CONFLICT';
            throw err;
          }
        }
        session.version = incomingVersion + 1;
        await client.query(
          `INSERT INTO payegis_escrow_checkpoints (session_id, version, state, payload, updated_at)
           VALUES ($1, $2, $3, $4, NOW())
           ON CONFLICT (session_id)
           DO UPDATE SET version = EXCLUDED.version, state = EXCLUDED.state, payload = EXCLUDED.payload, updated_at = NOW();`,
          [session.sessionId, session.version, session.state, JSON.stringify(session)]
        );
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      } finally {
        client.release();
      }
      return {
        backendType: this.backendType,
        version: session.version,
        persistedAt: new Date().toISOString(),
      };
    }

    const store = this._readDiskStore();
    const existingSession = store.sessions[session.sessionId];
    if (
      existingSession &&
      options.expectedVersion !== undefined &&
      Number(existingSession.version) !== Number(options.expectedVersion)
    ) {
      const err = new Error(
        `STALE_SESSION_VERSION_CONFLICT: Expected version ${options.expectedVersion}, but stored session is at version ${existingSession.version}.`
      );
      err.statusCode = 409;
      err.code = 'STALE_SESSION_VERSION_CONFLICT';
      throw err;
    }

    session.version = (existingSession ? Number(existingSession.version) : incomingVersion) + 1;
    store.sessions[session.sessionId] = structuredClone(session);
    store.latestSessionId = session.sessionId;
    const tmpFile = `${this.snapshotFile}.tmp.${process.pid}.${Date.now()}`;
    fs.writeFileSync(tmpFile, JSON.stringify(store, null, 2), 'utf8');
    fs.renameSync(tmpFile, this.snapshotFile);
    return {
      backendType: this.backendType,
      version: session.version,
      persistedAt: new Date().toISOString(),
    };
  }

  async archiveAndReplaceSession(previousSession, newSession) {
    await this.init();
    await this.appendOperationJournal({
      sessionId: previousSession.sessionId,
      requestId: `REQ-ARCHIVE-${Date.now()}`,
      phase: 'SESSION_ARCHIVED',
      operation: 'ARCHIVE_BEFORE_RESET',
      details: {
        archivedState: previousSession.state,
        orderId: previousSession.orderId,
        authorizationId: previousSession.authorizationId,
        newSessionId: newSession.sessionId,
      },
    });
    return this.saveSession(newSession);
  }

  async loadLatestSession() {
    await this.init();
    if (this.pgPool) {
      const res = await this.pgPool.query(
        `SELECT payload FROM payegis_escrow_checkpoints ORDER BY updated_at DESC LIMIT 1;`
      );
      return res.rows[0]?.payload || null;
    }

    const store = this._readDiskStore();
    if (store.latestSessionId && store.sessions[store.latestSessionId]) {
      return store.sessions[store.latestSessionId];
    }
    return null;
  }

  _readDiskStore() {
    try {
      const raw = fs.readFileSync(this.snapshotFile, 'utf8');
      return JSON.parse(raw);
    } catch (_) {
      return { sessions: {}, archivedSessions: [], latestSessionId: null };
    }
  }
}
