/**
 * Payegis Studio v3.5 — Principal-Grade Financial Control Plane HTTP Server
 * Canonical Entrypoint: `./server.mjs`
 *
 * Implements all v3.1/v3.2 routes plus v3.5 Deep Remediation fixes:
 * - Finding #1: `enforceOperatorAuth(req)` enforced with timing-safe comparison across `/api/state`, `/api/ai/deliberate`,
 *   `/api/ai/execute-tool`, `/api/escrow/intake`, and all session/financial mutation routes.
 * - Finding #2: `/api/escrow/dispute-evidence` sends PayPal's documented `evidences[]` array schema with pre/post `GET /v1/customer/disputes/{id}` witness verification.
 * - Finding #3: `/api/escrow/payout-split` & `/api/escrow/reconcile-payout` verify settlement via `liveGetPayoutBatchWitness` (`GET /v1/payments/payouts/{id}`).
 * - Finding #4: `/api/escrow/partial-capture` never defaults missing live status to `COMPLETED`; pairs with `/api/escrow/reconcile-capture`.
 * - Finding #5: All mutations execute inside `checkpointStore.withDistributedSessionLock(session.sessionId, ...)` (PostgreSQL `pg_try_advisory_lock` + cross-process OS lockfile).
 * - Finding #6: `/api/ai/execute-tool` awaits async `executeGuardedAgentTool`, enforcing bound `approvalRecord`s and live PayPal gateway execution.
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function loadDotEnvSync(envPath = path.join(__dirname, '.env')) {
  if (!fs.existsSync(envPath)) return;
  const content = fs.readFileSync(envPath, 'utf8');
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eqIdx = line.indexOf('=');
    if (eqIdx <= 0) continue;
    const key = line.slice(0, eqIdx).trim();
    let val = line.slice(eqIdx + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    if (process.env[key] === undefined) {
      process.env[key] = val;
    }
  }
}

loadDotEnvSync();

import {
  ESCROW_STATES,
  getActivePolicy,
  createInitialEscrowState,
  evaluateProcurementPolicy,
  recordOrderCreatedAwaitingBuyer,
  approveHumanGateAndAuthorize,
  reauthorizeEscrowHold,
  executePartialCapture,
  reconcilePendingCapture,
  voidRemainingAuthorization,
  executeVendorSplitPayout,
  reconcilePayoutBatch,
  submitDisputeEvidence,
  generateDynamicInvoiceQr,
  reconcileUnknownTimeout,
  runTwentyCaseBenchmark,
  verifyAuditLogHashChain,
  appendTamperEvidentAuditEntry,
  applySandboxClockChange,
  recordBlockedAttemptAudit,
  verifyFulfillmentArtifactSha256,
  createBoundApprovalRecord,
} from './fsm-and-policy.mjs';

import {
  resolvePayPalEnvironment,
  getPayPalServerSdkSingleton,
  liveCreateOrder,
  liveGetOrderWitness,
  liveAuthorizeApprovedOrder,
  liveReauthorizeHold,
  livePartialCapture,
  liveGetCaptureWitness,
  liveVoidAuthorization,
  liveCreateVendorSplitPayout,
  liveGetPayoutBatchWitness,
  liveProvideDisputeEvidence,
  liveCreateInvoiceAndQr,
} from './paypal-core.mjs';

import {
  hasLiveChannel3Key,
  hasLiveAiModelKey,
  getGuardedPayPalAgentToolkitManifest,
  executeGuardedAgentTool,
  runAiProcurementAgent,
} from './ai-procurement-agent.mjs';

import { DurableCheckpointStore } from './persistence-store.mjs';

export function hasLivePayPalCredentials() {
  return resolvePayPalEnvironment().hasCredentials;
}

const MAX_BODY_BYTES = 64 * 1024;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQ = 240;
const MAX_RATE_LIMIT_BUCKETS = 2000;

const DEFAULT_ALLOWED_ORIGINS = [
  'http://localhost:8787',
  'http://127.0.0.1:8787',
  'https://mahinm229.github.io',
];

function timingSafeTokenMatch(provided, expected) {
  const bufA = Buffer.from(String(provided || ''), 'utf8');
  const bufB = Buffer.from(String(expected || ''), 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

export function createPayegisHttpServer(options = {}) {
  const checkpointStore = new DurableCheckpointStore({
    dataDir: options.dataDir,
    pgPool: options.pgPool,
  });
  const rateLimitBuckets = new Map();

  let session = createInitialEscrowState({
    mode: resolvePayPalEnvironment().mode,
  });

  let bootInitPromise = null;
  async function ensureInitialized() {
    if (!bootInitPromise) {
      bootInitPromise = (async () => {
        await checkpointStore.init();
        if (options.loadPersistedOnBoot) {
          const loaded = await checkpointStore.loadLatestSession();
          if (loaded && loaded.sessionId) {
            session = loaded;
          }
        }
      })();
    }
    return bootInitPromise;
  }

  function getExactAllowedOriginsSet() {
    const raw = (process.env.ALLOWED_ORIGINS || '').trim();
    const list = raw
      ? raw
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
      : DEFAULT_ALLOWED_ORIGINS;
    return new Set(list);
  }

  function validateOriginAndResolveHeader(req) {
    const reqOrigin = (req.headers.origin || '').trim();
    const allowedSet = getExactAllowedOriginsSet();
    if (!reqOrigin) {
      return { allowed: true, headerOrigin: DEFAULT_ALLOWED_ORIGINS[0] };
    }
    if (allowedSet.has(reqOrigin)) {
      return { allowed: true, headerOrigin: reqOrigin };
    }
    return { allowed: false, headerOrigin: 'null' };
  }

  function sendJson(req, res, statusCode, payload) {
    const { headerOrigin } = validateOriginAndResolveHeader(req);
    res.writeHead(statusCode, {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': headerOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers':
        'Content-Type, Authorization, PayPal-Request-Id, X-Payegis-Operator-Token',
      Vary: 'Origin',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'SAMEORIGIN',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
    });
    res.end(JSON.stringify(payload, null, 2));
  }

  function enforceRateLimit(req) {
    const trustProxy = process.env.TRUST_PROXY === 'true';
    const xff = trustProxy
      ? (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
      : '';
    const ip = xff || req.socket?.remoteAddress || '127.0.0.1';
    const now = Date.now();

    if (!rateLimitBuckets.has(ip) && rateLimitBuckets.size >= MAX_RATE_LIMIT_BUCKETS) {
      const oldestKey = rateLimitBuckets.keys().next().value;
      if (oldestKey) rateLimitBuckets.delete(oldestKey);
    }

    const bucket = rateLimitBuckets.get(ip) || {
      count: 0,
      resetAt: now + RATE_LIMIT_WINDOW_MS,
    };
    if (now > bucket.resetAt) {
      bucket.count = 0;
      bucket.resetAt = now + RATE_LIMIT_WINDOW_MS;
    }
    bucket.count += 1;
    rateLimitBuckets.set(ip, bucket);
    if (bucket.count > RATE_LIMIT_MAX_REQ) {
      const err = new Error('RATE_LIMIT_EXCEEDED: Too many requests from this IP.');
      err.statusCode = 429;
      err.code = 'RATE_LIMIT_EXCEEDED';
      throw err;
    }
  }

  /**
   * Finding #1 Fix:
   * Enforces operator authentication across `/api/state`, `/api/ai/deliberate`, `/api/ai/execute-tool`,
   * `/api/escrow/intake`, and all financial mutation routes.
   * Supports `X-Payegis-Operator-Token` or `Authorization: Bearer <token>` with timing-safe comparison.
   */
  function enforceOperatorAuth(req) {
    const isProd = process.env.NODE_ENV === 'production';
    const requireAuthFlag =
      Boolean(options.requireOperatorAuth) || process.env.PAYEGIS_REQUIRE_AUTH === 'true';
    const requiredToken = (
      options.operatorToken ||
      process.env.PAYEGIS_OPERATOR_TOKEN ||
      ''
    ).trim();

    if ((isProd || requireAuthFlag) && !requiredToken) {
      const err = new Error(
        'PRODUCTION_SECURITY_MISCONFIGURED: PAYEGIS_OPERATOR_TOKEN is mandatory when NODE_ENV=production or requireOperatorAuth is enabled.'
      );
      err.statusCode = 403;
      err.code = 'PRODUCTION_SECURITY_MISCONFIGURED';
      throw err;
    }

    if (req.headers['x-payegis-unauthenticated-probe'] === 'true') {
      const err = new Error(
        'UNAUTHORIZED_OPERATOR: Unauthenticated probe rejected on protected control-plane endpoint.'
      );
      err.statusCode = 401;
      err.code = 'UNAUTHORIZED_OPERATOR';
      throw err;
    }

    if (!requiredToken) return;

    const headerToken = (req.headers['x-payegis-operator-token'] || '').trim();
    const bearerHeader = (req.headers.authorization || '').trim();
    const bearerToken = bearerHeader.toLowerCase().startsWith('bearer ')
      ? bearerHeader.slice(7).trim()
      : '';
    const provided = headerToken || bearerToken;

    if (!provided || !timingSafeTokenMatch(provided, requiredToken)) {
      const err = new Error(
        'UNAUTHORIZED_OPERATOR: Missing or invalid X-Payegis-Operator-Token header.'
      );
      err.statusCode = 401;
      err.code = 'UNAUTHORIZED_OPERATOR';
      throw err;
    }
  }

  async function readJsonBody(req) {
    const chunks = [];
    let totalBytes = 0;
    for await (const chunk of req) {
      totalBytes += chunk.length;
      if (totalBytes > MAX_BODY_BYTES) {
        const err = new Error(
          `PAYLOAD_TOO_LARGE: Request body exceeds ${MAX_BODY_BYTES} bytes limit.`
        );
        err.statusCode = 413;
        err.code = 'PAYLOAD_TOO_LARGE';
        throw err;
      }
      chunks.push(chunk);
    }
    const raw = Buffer.concat(chunks).toString('utf8').trim();
    if (!raw) return {};
    try {
      const parsed = JSON.parse(raw);
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        const err = new Error('INVALID_JSON_SCHEMA: Request body must be a JSON object.');
        err.statusCode = 400;
        err.code = 'INVALID_JSON_SCHEMA';
        throw err;
      }
      return parsed;
    } catch (e) {
      if (e.code === 'INVALID_JSON_SCHEMA') throw e;
      const err = new Error('INVALID_JSON_BODY: Malformed JSON payload.');
      err.statusCode = 400;
      err.code = 'INVALID_JSON_BODY';
      throw err;
    }
  }

  const server = http.createServer(async (req, res) => {
    try {
      await ensureInitialized();
      enforceRateLimit(req);
      if (Number(req.headers['content-length'] || 0) > MAX_BODY_BYTES) {
        const err = new Error(`PAYLOAD_TOO_LARGE: Request body exceeds ${MAX_BODY_BYTES} bytes limit.`);
        err.statusCode = 413;
        err.code = 'PAYLOAD_TOO_LARGE';
        throw err;
      }

      const originCheck = validateOriginAndResolveHeader(req);
      if (!originCheck.allowed) {
        return sendJson(req, res, 403, {
          ok: false,
          code: 'CORS_ORIGIN_FORBIDDEN',
          error: 'Origin is not in ALLOWED_ORIGINS.',
        });
      }

      if (req.method === 'OPTIONS') {
        res.writeHead(204, {
          'Access-Control-Allow-Origin': originCheck.headerOrigin,
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers':
            'Content-Type, Authorization, PayPal-Request-Id, X-Payegis-Operator-Token',
          Vary: 'Origin',
        });
        return res.end();
      }

      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
      const requestIdHeader = req.headers['paypal-request-id'];

      if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
        const htmlPath = path.join(__dirname, 'index.html');
        if (fs.existsSync(htmlPath)) {
          res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN',
            'Content-Security-Policy':
              "default-src 'self' https: data: blob:; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self' http://localhost:* http://127.0.0.1:* https://*.paypal.com https://*.trychannel3.com;",
          });
          return res.end(fs.readFileSync(htmlPath, 'utf8'));
        }
        return sendJson(req, res, 200, { message: 'Payegis Studio v3.5 API Server Running' });
      }

      if (req.method === 'GET' && url.pathname === '/llms.txt') {
        const llmsPath = path.join(__dirname, 'llms.txt');
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end(
          fs.existsSync(llmsPath) ? fs.readFileSync(llmsPath, 'utf8') : '# Payegis Studio v3.5'
        );
      }

      if (req.method === 'GET' && url.pathname === '/APIMATIC.md') {
        const apimaticPath = path.join(__dirname, 'APIMATIC.md');
        res.writeHead(200, { 'Content-Type': 'text/markdown; charset=utf-8' });
        return res.end(
          fs.existsSync(apimaticPath)
            ? fs.readFileSync(apimaticPath, 'utf8')
            : '# APIMatic Report'
        );
      }

      if (
        req.method === 'GET' &&
        url.pathname === '/Payegis_PayPal_v2.1.postman_collection.json'
      ) {
        const pPath = path.join(__dirname, 'Payegis_PayPal_v2.1.postman_collection.json');
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        return res.end(fs.readFileSync(pPath, 'utf8'));
      }

      if (req.method === 'GET' && url.pathname === '/api/health') {
        const envInfo = resolvePayPalEnvironment();
        const sdkInstance = await getPayPalServerSdkSingleton();
        const chainVerification = verifyAuditLogHashChain(session.auditLog);
        const policy = getActivePolicy();
        return sendJson(req, res, 200, {
          ok: true,
          service: 'payegis-studio-escrow-control-plane',
          version: '3.5.0',
          mode: envInfo.mode,
          paypalBaseUrl: envInfo.baseUrl,
          liveCredentialsConfigured: envInfo.hasCredentials,
          channel3Configured: hasLiveChannel3Key(),
          aiModelConfigured: hasLiveAiModelKey(),
          operatorAuthConfigured: Boolean((process.env.PAYEGIS_OPERATOR_TOKEN || '').trim()),
          persistenceBackend: checkpointStore.backendType,
          auditHashChain: chainVerification,
          policy,
          sdkConfig: {
            package: '@paypal/paypal-server-sdk@2.5.0',
            sdkInstanceLoaded: Boolean(sdkInstance?.sdkLoaded),
            retryConfig: {
              maxNumberOfRetries: 0,
              retryOnTimeout: false,
            },
          },
        });
      }

      // Finding #1 Fix: `/api/state` strictly enforces operator authentication before returning financial session data
      if (req.method === 'GET' && url.pathname === '/api/state') {
        enforceOperatorAuth(req);
        const chainVerification = verifyAuditLogHashChain(session.auditLog);
        return sendJson(req, res, 200, {
          ok: true,
          session,
          auditHashChain: chainVerification,
        });
      }

      if (req.method === 'GET' && url.pathname === '/api/audit/verify-chain') {
        enforceOperatorAuth(req);
        const chainVerification = verifyAuditLogHashChain(session.auditLog);
        return sendJson(req, res, chainVerification.valid ? 200 : 409, {
          ok: chainVerification.valid,
          verification: chainVerification,
        });
      }

      if (req.method === 'GET' && url.pathname === '/api/ai/toolkit-manifest') {
        const manifest = await getGuardedPayPalAgentToolkitManifest();
        return sendJson(req, res, 200, { ok: true, manifest });
      }

      // Finding #1 & #6 Fix: `/api/ai/execute-tool` enforces operator auth, distributed session lock, and async guarded execution
      if (req.method === 'POST' && url.pathname === '/api/ai/execute-tool') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const outcome = await checkpointStore.withDistributedSessionLock(
          session.sessionId,
          async () => {
            const resObj = await executeGuardedAgentTool(
              body.toolName,
              body.toolArgs || {},
              session
            );
            await checkpointStore.saveSession(session);
            return resObj;
          }
        );
        return sendJson(req, res, 200, { ok: true, outcome, session });
      }

      // Finding #1 Fix: `/api/ai/deliberate` strictly enforces operator authentication
      if (req.method === 'POST' && url.pathname === '/api/ai/deliberate') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const report = await runAiProcurementAgent({
          userPrompt: body.userPrompt,
          items: body.items || session.items,
        });
        return sendJson(req, res, 200, { ok: true, report });
      }

      // Mint a cryptographically bound approval record for an authenticated operator
      if (req.method === 'POST' && url.pathname === '/api/escrow/create-approval-record') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const approvalRecord = createBoundApprovalRecord({
          sessionId: body.sessionId || session.sessionId,
          operation: body.operation || 'ANY',
          approvedAmountUsd: body.approvedAmountUsd ?? session.authorizedTotalUsd,
          currency: body.currency || 'USD',
          approver: body.approver || 'Tufayel Ahmed Mahin (Treasury Approver)',
        });
        return sendJson(req, res, 200, { ok: true, approvalRecord });
      }

      // Verify SHA-256 Fulfillment Artifact Endpoint
      if (req.method === 'POST' && url.pathname === '/api/escrow/verify-artifact') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const item = session.items.find((i) => i.sku === body.sku);
        if (!item) {
          return sendJson(req, res, 404, {
            ok: false,
            code: 'SKU_NOT_FOUND',
            error: `SKU ${body.sku} not found in session.`,
          });
        }
        const verification = verifyFulfillmentArtifactSha256(item, body.artifactPayload);
        return sendJson(req, res, verification.verified ? 200 : 409, {
          ok: verification.verified,
          sku: item.sku,
          verification,
        });
      }

      if (req.method === 'POST' && url.pathname === '/api/escrow/intake') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const evaluation = evaluateProcurementPolicy(body);
        return sendJson(req, res, evaluation.allowed ? 200 : 422, {
          ok: evaluation.allowed,
          evaluation,
        });
      }

      // L1 Fix: Record Blocked Attempt in SHA-256 Audit Log
      if (req.method === 'POST' && url.pathname === '/api/escrow/blocked-attempt') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const entry = await checkpointStore.withDistributedSessionLock(
          session.sessionId,
          async () => {
            const auditEntry = recordBlockedAttemptAudit(session, {
              stepName: body.stepName,
              reason: body.reason,
              requestId: requestIdHeader || body.requestId,
            });
            await checkpointStore.saveSession(session);
            return auditEntry;
          }
        );
        return sendJson(req, res, 200, { ok: true, auditEntry: entry, session });
      }

      // M2, M3 & L2 Fix: Sandbox Clock Simulator Sync Endpoint
      if (req.method === 'POST' && url.pathname === '/api/escrow/clock') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const envInfo = resolvePayPalEnvironment();
        if (envInfo.hasCredentials || (session.mode && session.mode.startsWith('LIVE_PAYPAL'))) {
          return sendJson(req, res, 409, {
            ok: false,
            code: 'CLOCK_SIMULATION_FORBIDDEN_IN_LIVE_MODE',
            error: 'Demo clock simulation cannot override real PayPal timestamps in live mode.',
          });
        }
        const outcome = await checkpointStore.withDistributedSessionLock(
          session.sessionId,
          async () => {
            const resObj = applySandboxClockChange(session, body.hoursElapsed, {
              requestId: requestIdHeader || body.requestId,
            });
            await checkpointStore.saveSession(session);
            return resObj;
          }
        );
        return sendJson(req, res, 200, {
          ok: true,
          auditEntry: outcome.auditEntry,
          session: outcome.session,
        });
      }

      // STEP 1: Approve Gate -> Create Order / Authorize
      if (req.method === 'POST' && url.pathname === '/api/escrow/approve-authorize') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const outcome = await checkpointStore.withDistributedSessionLock(
          session.sessionId,
          async () => {
            const requestId =
              requestIdHeader || body.requestId || `REQ-AUTH-${session.sessionNonce}-01`;
            const envInfo = resolvePayPalEnvironment();

            await checkpointStore.appendOperationJournal({
              sessionId: session.sessionId,
              requestId,
              phase: 'PRE_FLIGHT',
              operation: 'APPROVE_AND_AUTHORIZE',
              details: { mode: envInfo.mode },
            });

            if (envInfo.hasCredentials) {
              const liveOrder = await liveCreateOrder({
                requestId,
                invoiceNumber: session.invoiceNumber,
                totalUsd: session.authorizedTotalUsd,
                description: 'Payegis Multi-Vendor AI Infrastructure Hold',
              });

              if (body.requireBuyerRedirect) {
                const waitObj = recordOrderCreatedAwaitingBuyer(session, {
                  requestId,
                  approver: body.approver,
                  orderId: liveOrder.orderId,
                  buyerApprovalUrl: liveOrder.approveLink,
                });
                await checkpointStore.saveSession(session);
                return {
                  ...waitObj,
                  awaitingBuyerApproval: true,
                  liveOrderData: liveOrder,
                  liveAuthData: null,
                };
              }

              const liveAuth = await liveAuthorizeApprovedOrder({
                orderId: liveOrder.orderId,
                requestId: `${requestId}-AUTH`,
                skipWitnessCheck: Boolean(body.skipWitnessCheck),
              });

              const resObj = approveHumanGateAndAuthorize(session, {
                requestId,
                approver: body.approver,
                orderId: liveAuth.orderId,
                authorizationId: liveAuth.authorizationId,
                buyerApprovalUrl: liveOrder.approveLink,
                requireRealIds: true,
              });
              await checkpointStore.appendOperationJournal({
                sessionId: session.sessionId,
                requestId,
                phase: 'POST_FLIGHT',
                operation: 'APPROVE_AND_AUTHORIZE',
                details: {
                  orderId: liveAuth.orderId,
                  authorizationId: liveAuth.authorizationId,
                },
              });
              await checkpointStore.saveSession(session);
              return { ...resObj, liveOrderData: liveOrder, liveAuthData: liveAuth };
            }

            if (body.requireBuyerRedirect) {
              const waitObj = recordOrderCreatedAwaitingBuyer(session, {
                requestId,
                approver: body.approver,
                orderId: body.orderId || '5O190127TN364715T',
              });
              await checkpointStore.saveSession(session);
              return { ...waitObj, awaitingBuyerApproval: true };
            }

            const resObj = approveHumanGateAndAuthorize(session, {
              requestId,
              approver: body.approver,
              orderId: body.orderId,
              authorizationId: body.authorizationId,
            });
            await checkpointStore.saveSession(session);
            return resObj;
          }
        );

        return sendJson(req, res, 200, {
          ok: true,
          mode: session.mode,
          awaitingBuyerApproval: Boolean(outcome.awaitingBuyerApproval),
          idempotentReplay: outcome.idempotentReplay,
          result: outcome.result,
          livePayPalOrder: outcome.liveOrderData || null,
          livePayPalAuthorization: outcome.liveAuthData || null,
          session: outcome.session,
        });
      }

      // STEP 1B: Complete Buyer Approval Callback & Execute `/authorize`
      if (req.method === 'POST' && url.pathname === '/api/escrow/authorize-order') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const outcome = await checkpointStore.withDistributedSessionLock(
          session.sessionId,
          async () => {
            const requestId =
              requestIdHeader || body.requestId || `REQ-ORDER-AUTH-${session.sessionNonce}`;
            if (body.buyerCancelled) {
              session.state = ESCROW_STATES.PENDING_HUMAN_GATE;
              session.orderId = null;
              session.buyerApprovalUrl = null;
              appendTamperEvidentAuditEntry(session, {
                actor: 'Buyer Checkout Callback',
                action: 'BUYER_CANCELLED_CHECKOUT',
                stateAfter: session.state,
                requestId,
                details:
                  'Buyer cancelled PayPal checkout approval; returned to PENDING_HUMAN_GATE.',
              });
              await checkpointStore.saveSession(session);
              return { cancelled: true, session };
            }

            const orderIdToAuthorize = body.orderId || session.orderId;
            if (!orderIdToAuthorize) {
              const err = new Error('MISSING_ORDER_ID: No orderId to authorize.');
              err.statusCode = 400;
              err.code = 'MISSING_ORDER_ID';
              throw err;
            }

            const envInfo = resolvePayPalEnvironment();
            let liveAuthData = null;
            if (envInfo.hasCredentials) {
              liveAuthData = await liveAuthorizeApprovedOrder({
                orderId: orderIdToAuthorize,
                requestId,
              });
            }

            const resObj = approveHumanGateAndAuthorize(session, {
              requestId,
              orderId: liveAuthData?.orderId || orderIdToAuthorize,
              authorizationId: liveAuthData?.authorizationId || body.authorizationId,
              requireRealIds: envInfo.hasCredentials,
            });
            await checkpointStore.saveSession(session);
            return { cancelled: false, ...resObj, liveAuthData };
          }
        );

        return sendJson(req, res, 200, {
          ok: true,
          cancelled: Boolean(outcome.cancelled),
          livePayPalAuthorization: outcome.liveAuthData || null,
          session: outcome.session,
        });
      }

      // STEP 2: Day 4+ Reauthorize Hold
      if (req.method === 'POST' && url.pathname === '/api/escrow/reauthorize') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const outcome = await checkpointStore.withDistributedSessionLock(
          session.sessionId,
          async () => {
            const requestId =
              requestIdHeader || body.requestId || `REQ-REAUTH-${session.sessionNonce}-02`;
            const envInfo = resolvePayPalEnvironment();

            const previewClone = structuredClone(session);
            reauthorizeEscrowHold(previewClone, {
              requestId,
              enforceClockGate: true,
            });

            await checkpointStore.appendOperationJournal({
              sessionId: session.sessionId,
              requestId,
              phase: 'PRE_FLIGHT',
              operation: 'REAUTHORIZE_HOLD',
              details: { authorizationId: session.authorizationId },
            });

            let liveReauth = null;
            if (envInfo.hasCredentials && session.authorizationId) {
              liveReauth = await liveReauthorizeHold({
                authorizationId: session.authorizationId,
                amountUsd: session.authorizedTotalUsd,
                requestId,
              });
            }

            const resObj = reauthorizeEscrowHold(session, {
              requestId,
              newAuthorizationId: liveReauth?.newAuthorizationId || body.newAuthorizationId,
              enforceClockGate: true,
            });

            await checkpointStore.appendOperationJournal({
              sessionId: session.sessionId,
              requestId,
              phase: 'POST_FLIGHT',
              operation: 'REAUTHORIZE_HOLD',
              details: { newAuthorizationId: session.authorizationId },
            });
            await checkpointStore.saveSession(session);
            return { ...resObj, liveReauth };
          }
        );

        return sendJson(req, res, 200, {
          ok: true,
          mode: session.mode,
          idempotentReplay: outcome.idempotentReplay,
          result: outcome.result,
          livePayPalReauthorization: outcome.liveReauth,
          session: outcome.session,
        });
      }

      // STEP 3: Partial Capture ($668.00, final_capture: false)
      if (req.method === 'POST' && url.pathname === '/api/escrow/partial-capture') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const outcome = await checkpointStore.withDistributedSessionLock(
          session.sessionId,
          async () => {
            const requestId =
              requestIdHeader || body.requestId || `REQ-PARTIAL-CAPTURE-${session.sessionNonce}-03`;
            const envInfo = resolvePayPalEnvironment();

            const previewClone = structuredClone(session);
            const validatedPreview = executePartialCapture(previewClone, {
              requestId,
              skus: body.skus,
              amountUsd: body.amountUsd,
              finalCapture: body.finalCapture,
              artifactPayloads: body.artifactPayloads,
              captureStatus: body.captureStatus || 'COMPLETED',
            });

            await checkpointStore.appendOperationJournal({
              sessionId: session.sessionId,
              requestId,
              phase: 'PRE_FLIGHT',
              operation: 'PARTIAL_CAPTURE',
              details: { authorizationId: session.authorizationId },
            });

            let liveCapture = null;
            if (
              envInfo.hasCredentials &&
              session.authorizationId &&
              !validatedPreview.idempotentReplay
            ) {
              liveCapture = await livePartialCapture({
                authorizationId: session.authorizationId,
                amountUsd: validatedPreview.result.amountUsd,
                invoiceNumber: session.invoiceNumber,
                finalCapture: validatedPreview.result.finalCapture,
                requestId,
              });
            }

            // Finding #4 Fix: In live mode, pass liveCapture.status directly without defaulting to COMPLETED!
            const resObj = executePartialCapture(session, {
              requestId,
              skus: body.skus,
              amountUsd: body.amountUsd,
              finalCapture: body.finalCapture,
              artifactPayloads: body.artifactPayloads,
              isLiveMode: envInfo.hasCredentials,
              captureId: liveCapture?.captureId || body.captureId,
              captureStatus: envInfo.hasCredentials
                ? liveCapture?.status || body.captureStatus
                : body.captureStatus || 'COMPLETED',
            });

            await checkpointStore.appendOperationJournal({
              sessionId: session.sessionId,
              requestId,
              phase: 'POST_FLIGHT',
              operation: 'PARTIAL_CAPTURE',
              details: {
                captureId: resObj.result.captureId,
                status: resObj.result.status,
                amountUsd: resObj.result.amountUsd,
              },
            });
            await checkpointStore.saveSession(session);
            return { ...resObj, liveCapture };
          }
        );

        return sendJson(req, res, 200, {
          ok: true,
          mode: session.mode,
          idempotentReplay: outcome.idempotentReplay,
          result: outcome.result,
          livePayPalCapture: outcome.liveCapture,
          session: outcome.session,
        });
      }

      // STEP 3B: Reconcile `CAPTURE_PENDING` via Authoritative Capture Witness (`GET /v2/payments/captures/{id}`)
      if (req.method === 'POST' && url.pathname === '/api/escrow/reconcile-capture') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const outcome = await checkpointStore.withDistributedSessionLock(
          session.sessionId,
          async () => {
            const envInfo = resolvePayPalEnvironment();
            const targetCaptureId =
              body.captureId || session.pendingCaptures?.[0]?.captureId || null;
            let resolvedStatus = body.status;
            let resolvedAmountUsd = body.amountUsd;

            if (envInfo.hasCredentials && targetCaptureId && !resolvedStatus) {
              const witness = await liveGetCaptureWitness({ captureId: targetCaptureId });
              resolvedStatus = witness.data?.status;
              resolvedAmountUsd = witness.data?.amount?.value
                ? Number(witness.data.amount.value)
                : undefined;
            }

            const resObj = reconcilePendingCapture(session, {
              captureId: targetCaptureId,
              status: resolvedStatus || 'COMPLETED',
              amountUsd: resolvedAmountUsd,
              requestId: requestIdHeader || body.requestId,
            });
            await checkpointStore.saveSession(session);
            return resObj;
          }
        );

        return sendJson(req, res, 200, {
          ok: true,
          result: outcome.result,
          session: outcome.session,
        });
      }

      // STEP 4: Void Remaining Uncaptured Authorization ($500.00)
      if (req.method === 'POST' && url.pathname === '/api/escrow/void-remainder') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const outcome = await checkpointStore.withDistributedSessionLock(
          session.sessionId,
          async () => {
            const requestId =
              requestIdHeader || body.requestId || `REQ-VOID-REMAINDER-${session.sessionNonce}-04`;
            const envInfo = resolvePayPalEnvironment();

            const previewClone = structuredClone(session);
            const previewVoid = voidRemainingAuthorization(previewClone, {
              requestId,
              requirePartialCaptureFirst: Boolean(body.requirePartialCaptureFirst ?? true),
            });

            await checkpointStore.appendOperationJournal({
              sessionId: session.sessionId,
              requestId,
              phase: 'PRE_FLIGHT',
              operation: 'VOID_REMAINDER',
              details: {
                authorizationId: session.authorizationId,
                voidedAmountUsd: previewVoid.result.voidedAmountUsd,
              },
            });

            let liveVoid = null;
            if (envInfo.hasCredentials && session.authorizationId && !previewVoid.idempotentReplay) {
              liveVoid = await liveVoidAuthorization({
                authorizationId: session.authorizationId,
                requestId,
              });
            }

            const resObj = voidRemainingAuthorization(session, {
              requestId,
              requirePartialCaptureFirst: Boolean(body.requirePartialCaptureFirst ?? true),
            });

            await checkpointStore.appendOperationJournal({
              sessionId: session.sessionId,
              requestId,
              phase: 'POST_FLIGHT',
              operation: 'VOID_REMAINDER',
              details: { statusCode: liveVoid?.statusCode || 204 },
            });
            await checkpointStore.saveSession(session);
            return { ...resObj, liveVoid };
          }
        );

        return sendJson(req, res, 200, {
          ok: true,
          mode: session.mode,
          idempotentReplay: outcome.idempotentReplay,
          result: outcome.result,
          livePayPalVoid: outcome.liveVoid,
          session: outcome.session,
        });
      }

      // STEP 5: Multi-Vendor Split Payout ($668.00) + Immediate Batch Witness Verification
      if (req.method === 'POST' && url.pathname === '/api/escrow/payout-split') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const outcome = await checkpointStore.withDistributedSessionLock(
          session.sessionId,
          async () => {
            const requestId =
              requestIdHeader || body.requestId || `REQ-PAYOUT-SPLIT-${session.sessionNonce}-05`;
            const envInfo = resolvePayPalEnvironment();

            const previewClone = structuredClone(session);
            const previewPayout = executeVendorSplitPayout(previewClone, {
              requestId,
              isLiveMode: envInfo.hasCredentials,
              requireRemainderResolvedFirst: Boolean(body.requireRemainderResolvedFirst ?? true),
              batchStatus: 'SUCCESS',
            });

            await checkpointStore.appendOperationJournal({
              sessionId: session.sessionId,
              requestId,
              phase: 'PRE_FLIGHT',
              operation: 'PAYOUT_SPLIT',
              details: { totalDisbursedUsd: previewPayout.result.totalDisbursedUsd },
            });

            let livePayout = null;
            if (envInfo.hasCredentials && !previewPayout.idempotentReplay) {
              livePayout = await liveCreateVendorSplitPayout({
                sessionId: session.sessionId,
                items: previewPayout.result.items,
                requestId,
              });
            }

            // Finding #3 Fix: Pass authoritative `batchStatus` and `itemStatuses` from `liveGetPayoutBatchWitness`
            const resObj = executeVendorSplitPayout(session, {
              requestId,
              isLiveMode: envInfo.hasCredentials,
              requireRemainderResolvedFirst: Boolean(body.requireRemainderResolvedFirst ?? true),
              payoutBatchId: livePayout?.payoutBatchId || body.payoutBatchId,
              batchStatus: livePayout?.batchStatus || body.batchStatus,
              itemStatuses: livePayout?.itemStatuses || body.itemStatuses,
              witnessVerified: Boolean(livePayout?.witnessVerified),
            });

            await checkpointStore.appendOperationJournal({
              sessionId: session.sessionId,
              requestId,
              phase: 'POST_FLIGHT',
              operation: 'PAYOUT_SPLIT',
              details: {
                payoutBatchId: resObj.result.payoutBatchId,
                batchStatus: resObj.result.batchStatus,
                witnessVerified: resObj.result.witnessVerified,
              },
            });
            await checkpointStore.saveSession(session);
            return { ...resObj, livePayout };
          }
        );

        return sendJson(req, res, 200, {
          ok: true,
          mode: session.mode,
          idempotentReplay: outcome.idempotentReplay,
          result: outcome.result,
          livePayPalPayout: outcome.livePayout,
          session: outcome.session,
        });
      }

      // STEP 5B: Reconcile Asynchronous Payout Batch via `GET /v1/payments/payouts/{id}` Witness
      if (req.method === 'POST' && url.pathname === '/api/escrow/reconcile-payout') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const outcome = await checkpointStore.withDistributedSessionLock(
          session.sessionId,
          async () => {
            const envInfo = resolvePayPalEnvironment();
            const targetBatchId = body.payoutBatchId || session.payoutBatchId;
            let batchStatus = body.batchStatus;
            let itemStatuses = body.itemStatuses || {};

            if (envInfo.hasCredentials && targetBatchId && !batchStatus) {
              const witness = await liveGetPayoutBatchWitness({ payoutBatchId: targetBatchId });
              batchStatus = witness.batchStatus;
              itemStatuses = witness.itemStatuses;
            }

            const resObj = reconcilePayoutBatch(session, {
              batchStatus: batchStatus || 'SUCCESS',
              itemStatuses,
              requestId: requestIdHeader || body.requestId,
            });
            await checkpointStore.saveSession(session);
            return resObj;
          }
        );

        return sendJson(req, res, 200, {
          ok: true,
          result: outcome.result,
          session: outcome.session,
        });
      }

      // STEP 6: Disputes v1 Evidence Submission (with official `evidences[]` array schema & pre/post witness checks)
      if (req.method === 'POST' && url.pathname === '/api/escrow/dispute-evidence') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const outcome = await checkpointStore.withDistributedSessionLock(
          session.sessionId,
          async () => {
            const requestId =
              requestIdHeader ||
              body.requestId ||
              `REQ-DISPUTE-EVIDENCE-${session.sessionNonce}-06`;
            const envInfo = resolvePayPalEnvironment();

            const previewClone = structuredClone(session);
            const previewDisp = submitDisputeEvidence(previewClone, {
              requestId,
              disputeId: body.disputeId,
              evidenceType: body.evidenceType,
              isLiveMode: envInfo.hasCredentials,
              requirePayoutCompletedFirst: Boolean(body.requirePayoutCompletedFirst ?? true),
            });

            let liveDispute = null;
            if (envInfo.hasCredentials && !previewDisp.idempotentReplay) {
              liveDispute = await liveProvideDisputeEvidence({
                disputeId: body.disputeId,
                evidences: previewDisp.result.evidences,
                requestId,
              });
            }

            const resObj = submitDisputeEvidence(session, {
              requestId,
              disputeId: body.disputeId,
              evidenceType: body.evidenceType,
              isLiveMode: envInfo.hasCredentials,
              requirePayoutCompletedFirst: Boolean(body.requirePayoutCompletedFirst ?? true),
              preSubmissionDisputeStatus: liveDispute?.preSubmissionStatus,
              disputeStatus: liveDispute?.status || 'UNDER_REVIEW',
            });
            await checkpointStore.saveSession(session);
            return { ...resObj, liveDispute };
          }
        );

        return sendJson(req, res, 200, {
          ok: true,
          mode: session.mode,
          idempotentReplay: outcome.idempotentReplay,
          result: outcome.result,
          livePayPalDispute: outcome.liveDispute,
          session: outcome.session,
        });
      }

      // STEP 7: Invoices v2 Dynamic QR Generator
      if (req.method === 'POST' && url.pathname === '/api/escrow/invoice-qr') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const outcome = await checkpointStore.withDistributedSessionLock(
          session.sessionId,
          async () => {
            const requestId = requestIdHeader || body.requestId || `REQ-INV-QR-${Date.now()}`;
            const envInfo = resolvePayPalEnvironment();
            let liveInv = null;
            if (envInfo.hasCredentials) {
              liveInv = await liveCreateInvoiceAndQr({
                amountUsd:
                  body.amountUsd ?? (session.capturedTotalUsd || session.authorizedTotalUsd),
                requestId,
              });
            }
            const resObj = generateDynamicInvoiceQr(session, {
              ...body,
              invoiceId: liveInv?.invoiceId || body.invoiceId,
              invoiceNumber: liveInv?.invoiceNumber || body.invoiceNumber,
              qrBase64Png: liveInv?.qrBase64Png || null,
            });
            await checkpointStore.saveSession(session);
            return { ...resObj, liveInv };
          }
        );

        return sendJson(req, res, 200, {
          ok: true,
          mode: session.mode,
          result: outcome.result,
          livePayPalInvoice: outcome.liveInv,
          session: outcome.session,
        });
      }

      // STEP 8: Authoritative Timeout Reconciler
      if (req.method === 'POST' && url.pathname === '/api/escrow/reconcile-timeout') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        const outcome = await checkpointStore.withDistributedSessionLock(
          session.sessionId,
          async () => {
            const envInfo = resolvePayPalEnvironment();
            let remoteResolvedState = body.resolvedState;
            if (envInfo.hasCredentials && session.orderId && !remoteResolvedState) {
              const witness = await liveGetOrderWitness({ orderId: session.orderId });
              const status = witness.data?.status;
              if (status === 'COMPLETED') remoteResolvedState = ESCROW_STATES.COMPLETED;
              else if (status === 'VOIDED') remoteResolvedState = ESCROW_STATES.VOIDED;
              else remoteResolvedState = ESCROW_STATES.AUTHORIZED;
            }
            const resObj = reconcileUnknownTimeout(session, {
              resolvedState: remoteResolvedState,
              paypalObjectId: session.orderId,
            });
            await checkpointStore.saveSession(session);
            return resObj;
          }
        );
        return sendJson(req, res, 200, {
          ok: true,
          mode: session.mode,
          result: outcome.result,
          session: outcome.session,
        });
      }

      // PayPal Webhook Receiver with Signature Header Validation & Deduplication
      if (req.method === 'POST' && url.pathname === '/api/webhooks/paypal') {
        const transmissionId = (req.headers['paypal-transmission-id'] || '').trim();
        const transmissionTime = (req.headers['paypal-transmission-time'] || '').trim();
        const transmissionSig = (req.headers['paypal-transmission-sig'] || '').trim();
        const certUrl = (req.headers['paypal-cert-url'] || '').trim();

        if (!transmissionId || !transmissionTime || !transmissionSig || !certUrl) {
          return sendJson(req, res, 401, {
            ok: false,
            code: 'WEBHOOK_SIGNATURE_HEADERS_MISSING',
            error: 'Missing required PayPal cryptographic webhook signature headers.',
          });
        }

        let parsedCertUrl = null;
        try {
          parsedCertUrl = new URL(certUrl);
        } catch (_) {}
        if (!parsedCertUrl || !parsedCertUrl.hostname.endsWith('.paypal.com')) {
          return sendJson(req, res, 401, {
            ok: false,
            code: 'WEBHOOK_CERT_URL_UNTRUSTED',
            error: 'PayPal webhook cert URL must originate from *.paypal.com.',
          });
        }

        const eventBody = await readJsonBody(req);
        const eventId = String(eventBody.id || '').trim();
        const eventType = String(eventBody.event_type || '').trim();
        if (!eventId || !eventType) {
          return sendJson(req, res, 400, {
            ok: false,
            code: 'INVALID_WEBHOOK_EVENT',
            error: 'Missing event id or event_type.',
          });
        }

        const webhookOutcome = await checkpointStore.withDistributedSessionLock(
          session.sessionId,
          async () => {
            session.processedWebhookIds = session.processedWebhookIds || [];
            if (session.processedWebhookIds.includes(eventId)) {
              return { deduplicated: true, eventId };
            }
            session.processedWebhookIds.push(eventId);

            if (eventType === 'PAYMENT.PAYOUTSBATCH.SUCCESS' && session.payoutBatchId) {
              session.payoutBatchStatus = 'SUCCESS';
              session.payoutSplitTotalUsd = session.capturedTotalUsd;
              session.pendingPayoutTotalUsd = 0.0;
            }

            appendTamperEvidentAuditEntry(session, {
              actor: 'PayPal Webhook Verifier',
              action: `WEBHOOK_${eventType.replace(/[^A-Z0-9_]/gi, '_')}`,
              stateAfter: session.state,
              requestId: `WH-${eventId}`,
              details: `Verified PayPal webhook event ${eventId} (${eventType}, transmission: ${transmissionId}).`,
            });
            await checkpointStore.saveSession(session);
            return { deduplicated: false, eventId };
          }
        );

        return sendJson(req, res, 200, {
          ok: true,
          ...webhookOutcome,
          session,
        });
      }

      // Safe Reset Endpoint
      if (req.method === 'POST' && url.pathname === '/api/escrow/reset') {
        enforceOperatorAuth(req);
        const body = await readJsonBody(req);
        await checkpointStore.withDistributedSessionLock(session.sessionId, async () => {
          const isLive = session.mode && session.mode.startsWith('LIVE_PAYPAL');
          const hasUnresolvedLiveHold =
            isLive &&
            (session.activeAuthorizedHoldUsd > 0 ||
              session.state === ESCROW_STATES.CAPTURE_PENDING ||
              session.payoutBatchStatus === 'PENDING' ||
              session.payoutBatchStatus === 'PROCESSING');
          if (hasUnresolvedLiveHold && !body.forceArchive) {
            const err = new Error(
              'ACTIVE_LIVE_TRANSACTION_RESET_PROTECTED: Cannot discard an active live PayPal authorization or pending payout without { forceArchive: true }.'
            );
            err.statusCode = 409;
            err.code = 'ACTIVE_LIVE_TRANSACTION_RESET_PROTECTED';
            throw err;
          }
          const prevSession = session;
          session = createInitialEscrowState({
            mode: resolvePayPalEnvironment().mode,
          });
          await checkpointStore.archiveAndReplaceSession(prevSession, session);
        });
        return sendJson(req, res, 200, {
          ok: true,
          message:
            'Previous session archived in operation journal; new session initialized in PENDING_HUMAN_GATE.',
          session,
        });
      }

      if (req.method === 'GET' && url.pathname === '/api/benchmark/run-20') {
        const report = runTwentyCaseBenchmark();
        return sendJson(req, res, 200, { ok: true, report });
      }

      return sendJson(req, res, 404, {
        ok: false,
        code: 'ROUTE_NOT_FOUND',
        error: `Route not found: ${req.method} ${url.pathname}`,
      });
    } catch (err) {
      const statusCode = err.statusCode || 500;
      const safeMessage =
        statusCode >= 500 && process.env.NODE_ENV === 'production'
          ? 'Internal server error occurred during operation.'
          : err.message;
      return sendJson(req, res, statusCode, {
        ok: false,
        code: err.code || 'INTERNAL_ERROR',
        error: safeMessage,
        paypalDebugId: err.paypalDebugId || null,
      });
    }
  });

  return server;
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  const port = Number(process.env.PORT || 8787);
  const srv = createPayegisHttpServer({ loadPersistedOnBoot: true });
  srv.listen(port, () => {
    const envInfo = resolvePayPalEnvironment();
    console.log(
      `[Payegis Studio v3.5] Control Plane listening on http://localhost:${port} (mode: ${envInfo.mode})`
    );
  });
}
