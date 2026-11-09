/**
 * Payegis Studio v3.5 — Complete Live PayPal Sandbox & Server SDK Integration Module
 * Canonical Module: `./paypal-core.mjs`
 *
 * Implements Phase 2A–2H + v3.5 Deep Remediation Fixes:
 * - Finding #2: `liveGetDisputeWitness` (`GET /v1/customer/disputes/{id}`) + `liveProvideDisputeEvidence` using PayPal's official `evidences: [{ evidence_type, evidence_info: { tracking_info }, notes }]` schema and post-submission verification.
 * - Finding #3: `liveCreateVendorSplitPayout` (`POST /v1/payments/payouts`) automatically invokes `liveGetPayoutBatchWitness` (`GET /v1/payments/payouts/{batch_id}`) to extract authoritative batch & item-level settlement status (`SUCCESS`, `PENDING`, `PROCESSING`, `DENIED`, `FAILED`).
 * - Finding #4: `livePartialCapture` strictly validates authoritative `status` (never defaults missing status to `COMPLETED`), verifies amount/currency, and pairs with `liveGetCaptureWitness` (`GET /v2/payments/captures/{id}`).
 */

const PAYPAL_TIMEOUT_MS = 15000;

let cachedOAuthToken = {
  accessToken: null,
  expiresAtMs: 0,
  baseUrl: null,
  clientIdHash: null,
};

let cachedSdkSingleton = null;

export class PayPalApiError extends Error {
  constructor(message, statusCode, paypalDebugId = null, safeDetails = null) {
    super(message);
    this.name = 'PayPalApiError';
    this.statusCode = statusCode || 502;
    this.code = 'PAYPAL_API_ERROR';
    this.paypalDebugId = paypalDebugId;
    this.safeDetails = safeDetails;
  }
}

export function clearPayPalTokenCache() {
  cachedOAuthToken = { accessToken: null, expiresAtMs: 0, baseUrl: null, clientIdHash: null };
}

export function resolvePayPalEnvironment() {
  const envRaw = String(process.env.PAYPAL_ENV || 'sandbox').toLowerCase();
  const isProduction = envRaw === 'production' || envRaw === 'live';

  if (isProduction) {
    if (process.env.ALLOW_LIVE_PRODUCTION !== 'true') {
      const err = new PayPalApiError(
        'PRODUCTION_SAFETY_LOCK: PAYPAL_ENV=production requires explicit ALLOW_LIVE_PRODUCTION=true to prevent accidental real-money execution.',
        403
      );
      err.code = 'PRODUCTION_SAFETY_LOCK';
      throw err;
    }
    if (!(process.env.PAYEGIS_OPERATOR_TOKEN || '').trim()) {
      const err = new PayPalApiError(
        'PRODUCTION_AUTH_REQUIRED: PAYEGIS_OPERATOR_TOKEN must be configured when PAYPAL_ENV=production.',
        403
      );
      err.code = 'PRODUCTION_AUTH_REQUIRED';
      throw err;
    }
  }

  const baseUrl =
    process.env.PAYPAL_API_BASE_URL ||
    (isProduction ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com');

  const id = (process.env.PAYPAL_CLIENT_ID || '').trim();
  const secret = (process.env.PAYPAL_CLIENT_SECRET || '').trim();
  const hasCredentials =
    Boolean(id && secret) &&
    id !== 'your_paypal_sandbox_client_id_here' &&
    secret !== 'your_paypal_sandbox_client_secret_here';

  const mode = !hasCredentials
    ? 'OFFLINE_SIMULATOR'
    : isProduction
    ? 'LIVE_PAYPAL_PRODUCTION'
    : 'LIVE_PAYPAL_SANDBOX';

  return {
    isProduction,
    baseUrl,
    hasCredentials,
    mode,
    clientId: id,
    clientSecret: secret,
  };
}

export async function getPayPalServerSdkSingleton() {
  const env = resolvePayPalEnvironment();
  if (!env.hasCredentials) return null;
  if (cachedSdkSingleton) return cachedSdkSingleton;
  try {
    const sdk = await import('@paypal/paypal-server-sdk');
    const client = new sdk.Client({
      clientCredentialsAuthCredentials: {
        oAuthClientId: env.clientId,
        oAuthClientSecret: env.clientSecret,
      },
      timeout: PAYPAL_TIMEOUT_MS,
      environment: env.isProduction ? sdk.Environment.Production : sdk.Environment.Sandbox,
      retryConfig: {
        maxNumberOfRetries: 0,
        retryOnTimeout: false,
        retryInterval: 1,
        maximumRetryWaitTime: 0,
        backoffFactor: 2,
        httpStatusCodesToRetry: [],
        httpMethodsToRetry: [sdk.HttpMethod.Get],
      },
    });
    cachedSdkSingleton = {
      sdkLoaded: true,
      ordersController: new sdk.OrdersController(client),
      paymentsController: new sdk.PaymentsController(client),
    };
    return cachedSdkSingleton;
  } catch (_) {
    return null;
  }
}

async function parsePayPalResponse(res, endpointLabel) {
  const debugId = res.headers?.get?.('paypal-debug-id') || null;
  if (res.status === 204) {
    return { statusCode: 204, debugId, data: null };
  }
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch (_) {
    data = { rawText: text.slice(0, 200) };
  }
  if (!res.ok) {
    const issue =
      data?.details?.[0]?.issue ||
      data?.name ||
      data?.error_description ||
      data?.message ||
      `HTTP ${res.status}`;
    throw new PayPalApiError(
      `PayPal ${endpointLabel} failed (${res.status}): ${issue}${
        debugId ? ` [paypal-debug-id: ${debugId}]` : ''
      }`,
      res.status,
      debugId,
      { name: data?.name, issue: data?.details?.[0]?.issue, debugId }
    );
  }
  return { statusCode: res.status, debugId, data };
}

export async function getLivePayPalAccessToken() {
  const env = resolvePayPalEnvironment();
  if (!env.hasCredentials) {
    throw new PayPalApiError(
      'PAYPAL_CREDENTIALS_MISSING: Set PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET.',
      401
    );
  }

  const now = Date.now();
  if (
    cachedOAuthToken.accessToken &&
    cachedOAuthToken.baseUrl === env.baseUrl &&
    cachedOAuthToken.clientIdHash === env.clientId &&
    now < cachedOAuthToken.expiresAtMs
  ) {
    return {
      accessToken: cachedOAuthToken.accessToken,
      baseUrl: env.baseUrl,
      mode: env.mode,
      cached: true,
    };
  }

  const basic = Buffer.from(`${env.clientId}:${env.clientSecret}`).toString('base64');
  const res = await fetch(`${env.baseUrl}/v1/oauth2/token`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${basic}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials',
    signal: AbortSignal.timeout(PAYPAL_TIMEOUT_MS),
  });
  const parsed = await parsePayPalResponse(res, 'OAuth2 Token (POST /v1/oauth2/token)');
  const expiresInSec = Number(parsed.data?.expires_in || 3600);
  cachedOAuthToken = {
    accessToken: parsed.data.access_token,
    expiresAtMs: now + Math.max(60, expiresInSec - 60) * 1000,
    baseUrl: env.baseUrl,
    clientIdHash: env.clientId,
  };

  return {
    accessToken: parsed.data.access_token,
    baseUrl: env.baseUrl,
    mode: env.mode,
    debugId: parsed.debugId,
    cached: false,
  };
}

/**
 * 1. Create Order (`POST /v2/checkout/orders` with `intent: "AUTHORIZE"`)
 */
export async function liveCreateOrder({
  requestId,
  invoiceNumber,
  totalUsd,
  description,
  returnUrl = 'https://mahinm229.github.io/payegis-studio-paypal-ai-hackathon/?paypal_approved=1',
  cancelUrl = 'https://mahinm229.github.io/payegis-studio-paypal-ai-hackathon/?paypal_cancelled=1',
}) {
  const { accessToken, baseUrl } = await getLivePayPalAccessToken();
  const res = await fetch(`${baseUrl}/v2/checkout/orders`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'PayPal-Request-Id': requestId,
      Prefer: 'return=representation',
    },
    body: JSON.stringify({
      intent: 'AUTHORIZE',
      purchase_units: [
        {
          reference_id: 'PAYEGIS-ESCROW-UNIT-01',
          invoice_id: invoiceNumber,
          description: description || 'Payegis Multi-Vendor AI Infrastructure Hold',
          amount: {
            currency_code: 'USD',
            value: Number(totalUsd).toFixed(2),
          },
        },
      ],
      payment_source: {
        paypal: {
          experience_context: {
            brand_name: 'Payegis Studio Control Plane',
            user_action: 'CONTINUE',
            return_url: returnUrl,
            cancel_url: cancelUrl,
          },
        },
      },
    }),
    signal: AbortSignal.timeout(PAYPAL_TIMEOUT_MS),
  });

  const created = await parsePayPalResponse(res, 'Create Order (POST /v2/checkout/orders)');
  const orderId = created.data?.id;
  if (!orderId) {
    throw new PayPalApiError('PayPal Create Order returned no order id.', 502, created.debugId);
  }
  const approveLink =
    (created.data.links || []).find((l) => l.rel === 'payer-action' || l.rel === 'approve')?.href ||
    `https://www.sandbox.paypal.com/checkoutnow?token=${orderId}`;

  return {
    orderId,
    status: created.data.status,
    approveLink,
    debugId: created.debugId,
  };
}

/**
 * 2. Get Authoritative Order Witness (`GET /v2/checkout/orders/{order_id}`)
 */
export async function liveGetOrderWitness({ orderId }) {
  const { accessToken, baseUrl } = await getLivePayPalAccessToken();
  const res = await fetch(`${baseUrl}/v2/checkout/orders/${encodeURIComponent(orderId)}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    signal: AbortSignal.timeout(PAYPAL_TIMEOUT_MS),
  });
  return parsePayPalResponse(res, `Get Order Witness (GET /v2/checkout/orders/${orderId})`);
}

/**
 * 3. Authorize Buyer-Approved Order (`POST /v2/checkout/orders/{order_id}/authorize`)
 */
export async function liveAuthorizeApprovedOrder({ orderId, requestId, skipWitnessCheck = false }) {
  const { accessToken, baseUrl } = await getLivePayPalAccessToken();

  if (!skipWitnessCheck) {
    const witness = await liveGetOrderWitness({ orderId });
    const orderStatus = witness.data?.status;
    if (orderStatus && orderStatus !== 'APPROVED' && orderStatus !== 'COMPLETED') {
      const err = new PayPalApiError(
        `BUYER_APPROVAL_INCOMPLETE: Order ${orderId} has status ${orderStatus} (buyer must approve order at PayPal checkout URL before authorization can be executed).`,
        409,
        witness.debugId
      );
      err.code = 'BUYER_APPROVAL_INCOMPLETE';
      throw err;
    }
  }

  const res = await fetch(
    `${baseUrl}/v2/checkout/orders/${encodeURIComponent(orderId)}/authorize`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'PayPal-Request-Id': requestId,
        Prefer: 'return=representation',
      },
      body: JSON.stringify({}),
      signal: AbortSignal.timeout(PAYPAL_TIMEOUT_MS),
    }
  );
  const parsed = await parsePayPalResponse(
    res,
    `Authorize Order (POST /v2/checkout/orders/${orderId}/authorize)`
  );
  const authObj = parsed.data?.purchase_units?.[0]?.payments?.authorizations?.[0] || null;
  if (!authObj?.id) {
    throw new PayPalApiError(
      `MISSING_AUTHORIZATION_ID: PayPal /authorize response for order ${orderId} did not contain an authorization ID.`,
      502,
      parsed.debugId
    );
  }
  return {
    orderId: parsed.data.id,
    authorizationId: authObj.id,
    authorizationStatus: authObj.status || 'CREATED',
    authorizedAmountUsd: Number(authObj.amount?.value || 0),
    createTime: authObj.create_time || new Date().toISOString(),
    expirationTime: authObj.expiration_time || null,
    debugId: parsed.debugId,
  };
}

/**
 * 4. Get Authoritative Authorization Witness (`GET /v2/payments/authorizations/{authorization_id}`)
 */
export async function liveGetAuthorizationWitness({ authorizationId }) {
  const { accessToken, baseUrl } = await getLivePayPalAccessToken();
  const res = await fetch(
    `${baseUrl}/v2/payments/authorizations/${encodeURIComponent(authorizationId)}`,
    {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      signal: AbortSignal.timeout(PAYPAL_TIMEOUT_MS),
    }
  );
  return parsePayPalResponse(
    res,
    `Get Authorization Witness (GET /v2/payments/authorizations/${authorizationId})`
  );
}

/**
 * 5. Reauthorize Hold (`POST /v2/payments/authorizations/{authorization_id}/reauthorize`)
 */
export async function liveReauthorizeHold({ authorizationId, amountUsd, requestId }) {
  const { accessToken, baseUrl } = await getLivePayPalAccessToken();
  const res = await fetch(
    `${baseUrl}/v2/payments/authorizations/${encodeURIComponent(authorizationId)}/reauthorize`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'PayPal-Request-Id': requestId,
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        amount: {
          currency_code: 'USD',
          value: Number(amountUsd).toFixed(2),
        },
      }),
      signal: AbortSignal.timeout(PAYPAL_TIMEOUT_MS),
    }
  );
  const parsed = await parsePayPalResponse(
    res,
    `Reauthorize Hold (POST /v2/payments/authorizations/${authorizationId}/reauthorize)`
  );
  if (!parsed.data?.id) {
    throw new PayPalApiError(
      'PayPal Reauthorize response did not return a new authorization ID.',
      502,
      parsed.debugId
    );
  }
  return {
    newAuthorizationId: parsed.data.id,
    status: parsed.data.status || 'CREATED',
    debugId: parsed.debugId,
  };
}

/**
 * 6. Partial Capture (`POST /v2/payments/authorizations/{authorization_id}/capture`)
 * Finding #4 Fix: Never defaults missing `status` to `COMPLETED`! Validates authoritative status, currency, and amount.
 */
export async function livePartialCapture({
  authorizationId,
  amountUsd,
  invoiceNumber,
  finalCapture = false,
  requestId,
}) {
  const { accessToken, baseUrl } = await getLivePayPalAccessToken();
  const res = await fetch(
    `${baseUrl}/v2/payments/authorizations/${encodeURIComponent(authorizationId)}/capture`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'PayPal-Request-Id': requestId,
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        amount: {
          currency_code: 'USD',
          value: Number(amountUsd).toFixed(2),
        },
        invoice_id: invoiceNumber,
        final_capture: Boolean(finalCapture),
        note_to_payer:
          'Payegis Studio partial capture for verified delivered tranches; uncaptured remainder held under SLA guard.',
      }),
      signal: AbortSignal.timeout(PAYPAL_TIMEOUT_MS),
    }
  );
  const parsed = await parsePayPalResponse(
    res,
    `Partial Capture (POST /v2/payments/authorizations/${authorizationId}/capture)`
  );
  if (!parsed.data?.id) {
    throw new PayPalApiError('PayPal Capture response missing capture ID.', 502, parsed.debugId);
  }
  const authoritativeStatus = String(parsed.data?.status || '').trim().toUpperCase();
  if (!authoritativeStatus) {
    const err = new PayPalApiError(
      'MISSING_AUTHORITATIVE_CAPTURE_STATUS: PayPal Capture response did not include a capture status.',
      502,
      parsed.debugId
    );
    err.code = 'MISSING_AUTHORITATIVE_CAPTURE_STATUS';
    throw err;
  }

  if (parsed.data?.amount) {
    const respCurr = String(parsed.data.amount.currency_code || 'USD').toUpperCase();
    const respCents = Math.round(Number(parsed.data.amount.value) * 100);
    const reqCents = Math.round(Number(amountUsd) * 100);
    if (respCurr !== 'USD' || respCents !== reqCents) {
      const err = new PayPalApiError(
        `CAPTURE_RESPONSE_AMOUNT_MISMATCH: Expected $${Number(amountUsd).toFixed(
          2
        )} USD, got ${parsed.data.amount.value} ${respCurr}.`,
        502,
        parsed.debugId
      );
      err.code = 'CAPTURE_RESPONSE_AMOUNT_MISMATCH';
      throw err;
    }
  }

  return {
    captureId: parsed.data.id,
    status: authoritativeStatus,
    capturedAmountUsd: Number(parsed.data.amount?.value ?? amountUsd),
    currency: parsed.data.amount?.currency_code || 'USD',
    debugId: parsed.debugId,
  };
}

/**
 * 6B. Authoritative Capture Witness (`GET /v2/payments/captures/{capture_id}`)
 */
export async function liveGetCaptureWitness({ captureId }) {
  const { accessToken, baseUrl } = await getLivePayPalAccessToken();
  const res = await fetch(
    `${baseUrl}/v2/payments/captures/${encodeURIComponent(captureId)}`,
    {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      signal: AbortSignal.timeout(PAYPAL_TIMEOUT_MS),
    }
  );
  return parsePayPalResponse(
    res,
    `Get Capture Witness (GET /v2/payments/captures/${captureId})`
  );
}

/**
 * 7. Void Remaining Uncaptured Authorization (`POST /v2/payments/authorizations/{authorization_id}/void`)
 */
export async function liveVoidAuthorization({ authorizationId, requestId }) {
  const { accessToken, baseUrl } = await getLivePayPalAccessToken();
  const res = await fetch(
    `${baseUrl}/v2/payments/authorizations/${encodeURIComponent(authorizationId)}/void`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'PayPal-Request-Id': requestId,
      },
      signal: AbortSignal.timeout(PAYPAL_TIMEOUT_MS),
    }
  );
  const parsed = await parsePayPalResponse(
    res,
    `Void Authorization (POST /v2/payments/authorizations/${authorizationId}/void)`
  );
  return {
    statusCode: parsed.statusCode,
    debugId: parsed.debugId,
  };
}

/**
 * 8A. Get Payout Batch & Item-Level Witness (`GET /v1/payments/payouts/{payout_batch_id}`)
 * Finding #3 Fix: Extracts both `batch_header.batch_status` and item-level `items[].transaction_status`.
 */
export async function liveGetPayoutBatchWitness({ payoutBatchId }) {
  const { accessToken, baseUrl } = await getLivePayPalAccessToken();
  const res = await fetch(
    `${baseUrl}/v1/payments/payouts/${encodeURIComponent(payoutBatchId)}`,
    {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      signal: AbortSignal.timeout(PAYPAL_TIMEOUT_MS),
    }
  );
  const parsed = await parsePayPalResponse(
    res,
    `Get Payout Batch Witness (GET /v1/payments/payouts/${payoutBatchId})`
  );

  const batchStatus = parsed.data?.batch_header?.batch_status || 'PENDING';
  const rawItems = Array.isArray(parsed.data?.items) ? parsed.data.items : [];
  const itemStatuses = {};
  for (const item of rawItems) {
    const status = String(item?.transaction_status || batchStatus).toUpperCase();
    const senderItemId = item?.payout_item?.sender_item_id;
    const receiver = item?.payout_item?.receiver;
    if (senderItemId) itemStatuses[senderItemId] = status;
    if (receiver) itemStatuses[receiver] = status;
  }

  return {
    ...parsed,
    payoutBatchId,
    batchStatus,
    itemStatuses,
    items: rawItems,
  };
}

/**
 * 8B. Multi-Vendor Split Payout (`POST /v1/payments/payouts`) + Authoritative Batch Witness Verification
 * Finding #3 Fix: Automatically queries `liveGetPayoutBatchWitness` after creation so settlement is verified against the authoritative Payout Batch Witness!
 */
export async function liveCreateVendorSplitPayout({
  sessionId,
  items,
  requestId,
  skipImmediateWitness = false,
}) {
  const { accessToken, baseUrl } = await getLivePayPalAccessToken();
  const res = await fetch(`${baseUrl}/v1/payments/payouts`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'PayPal-Request-Id': requestId,
    },
    body: JSON.stringify({
      sender_batch_header: {
        sender_batch_id: `PAYEGIS-${sessionId}-${requestId}`,
        email_subject: 'Payegis Studio Verified Multi-Vendor Tranche Settlement',
        email_message:
          'Your delivered infrastructure tranche passed SHA-256 verification and has been settled via PayPal Payouts v1.',
      },
      items,
    }),
    signal: AbortSignal.timeout(PAYPAL_TIMEOUT_MS),
  });
  const parsed = await parsePayPalResponse(res, 'Split Payout (POST /v1/payments/payouts)');
  const payoutBatchId = parsed.data?.batch_header?.payout_batch_id;
  if (!payoutBatchId) {
    throw new PayPalApiError('PayPal Payouts response missing payout_batch_id.', 502, parsed.debugId);
  }

  let batchStatus = parsed.data?.batch_header?.batch_status || 'PENDING';
  let itemStatuses = {};
  let witnessVerified = false;

  if (!skipImmediateWitness) {
    try {
      const witness = await liveGetPayoutBatchWitness({ payoutBatchId });
      batchStatus = witness.batchStatus || batchStatus;
      itemStatuses = witness.itemStatuses || {};
      witnessVerified = true;
    } catch (_) {
      // If immediate GET witness is not yet indexed on PayPal, keep batchStatus from POST (typically PENDING)
    }
  }

  return {
    payoutBatchId,
    batchStatus,
    itemStatuses,
    witnessVerified,
    debugId: parsed.debugId,
  };
}

/**
 * 9A. Get Customer Dispute Details Witness (`GET /v1/customer/disputes/{id}`)
 */
export async function liveGetDisputeWitness({ disputeId }) {
  const { accessToken, baseUrl } = await getLivePayPalAccessToken();
  const res = await fetch(
    `${baseUrl}/v1/customer/disputes/${encodeURIComponent(disputeId)}`,
    {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      signal: AbortSignal.timeout(PAYPAL_TIMEOUT_MS),
    }
  );
  return parsePayPalResponse(
    res,
    `Get Dispute Witness (GET /v1/customer/disputes/${disputeId})`
  );
}

/**
 * 9B. Customer Disputes v1 Provide Evidence (`POST /v1/customer/disputes/{id}/provide-evidence`)
 * Finding #2 Fix:
 * - Pre-verifies dispute existence & open status via `GET /v1/customer/disputes/{id}` (when available).
 * - Sends PayPal's documented Customer Disputes v1 `evidences: [{ evidence_type, evidence_info: { tracking_info }, notes }]` structure.
 * - Performs post-submission status verification.
 */
export async function liveProvideDisputeEvidence({
  disputeId,
  evidenceType = 'PROOF_OF_FULFILLMENT',
  trackingInfo,
  notes,
  evidences,
  requestId,
  skipPreWitness = false,
  skipPostWitness = false,
}) {
  const { accessToken, baseUrl } = await getLivePayPalAccessToken();

  let preStatus = null;
  if (!skipPreWitness) {
    try {
      const preWitness = await liveGetDisputeWitness({ disputeId });
      preStatus = String(preWitness.data?.status || '').toUpperCase();
      if (preStatus === 'RESOLVED' || preStatus === 'CLOSED') {
        const err = new PayPalApiError(
          `DISPUTE_ALREADY_CLOSED: Dispute ${disputeId} has status ${preStatus} and cannot accept new evidence.`,
          409,
          preWitness.debugId
        );
        err.code = 'DISPUTE_ALREADY_CLOSED';
        throw err;
      }
    } catch (e) {
      if (e.code === 'DISPUTE_ALREADY_CLOSED') throw e;
      // Allow direct POST if mock/test only stubs the POST endpoint
    }
  }

  const normalizedEvidences =
    Array.isArray(evidences) && evidences.length > 0
      ? evidences
      : [
          {
            evidence_type: evidenceType || 'PROOF_OF_FULFILLMENT',
            evidence_info: {
              tracking_info: trackingInfo,
            },
            notes,
          },
        ];

  const requestBody = {
    evidences: normalizedEvidences,
  };

  const res = await fetch(
    `${baseUrl}/v1/customer/disputes/${encodeURIComponent(disputeId)}/provide-evidence`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'PayPal-Request-Id': requestId,
      },
      body: JSON.stringify(requestBody),
      signal: AbortSignal.timeout(PAYPAL_TIMEOUT_MS),
    }
  );
  const parsed = await parsePayPalResponse(
    res,
    `Provide Dispute Evidence (POST /v1/customer/disputes/${disputeId}/provide-evidence)`
  );

  let finalStatus = parsed.data?.status || 'UNDER_REVIEW';
  if (!skipPostWitness) {
    try {
      const postWitness = await liveGetDisputeWitness({ disputeId });
      if (postWitness.data?.status) {
        finalStatus = postWitness.data.status;
      }
    } catch (_) {}
  }

  return {
    disputeId,
    preSubmissionStatus: preStatus,
    status: finalStatus,
    evidencesSubmitted: normalizedEvidences,
    debugId: parsed.debugId,
  };
}

/**
 * 10. Invoices v2 Next Number + Draft Invoice + QR Code (`POST /v2/invoicing/invoices/{id}/qr-code`)
 */
export async function liveCreateInvoiceAndQr({ amountUsd, requestId }) {
  const { accessToken, baseUrl } = await getLivePayPalAccessToken();

  const numRes = await fetch(`${baseUrl}/v2/invoicing/generate-next-invoice-number`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    signal: AbortSignal.timeout(PAYPAL_TIMEOUT_MS),
  });
  const numParsed = await parsePayPalResponse(
    numRes,
    'Generate Invoice Number (POST /v2/invoicing/generate-next-invoice-number)'
  );
  const invoiceNumber = numParsed.data?.invoice_number || `INV-2026-${Date.now() % 10000}`;

  const draftRes = await fetch(`${baseUrl}/v2/invoicing/invoices`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'PayPal-Request-Id': requestId,
      Prefer: 'return=representation',
    },
    body: JSON.stringify({
      detail: {
        invoice_number: invoiceNumber,
        currency_code: 'USD',
        note: 'Payegis Studio Multi-Vendor Settlement Invoice',
      },
      items: [
        {
          name: 'Verified AI Infrastructure Bundle',
          quantity: '1',
          unit_amount: {
            currency_code: 'USD',
            value: Number(amountUsd).toFixed(2),
          },
        },
      ],
    }),
    signal: AbortSignal.timeout(PAYPAL_TIMEOUT_MS),
  });
  const draftParsed = await parsePayPalResponse(
    draftRes,
    'Create Draft Invoice (POST /v2/invoicing/invoices)'
  );
  const invoiceId = draftParsed.data?.id;
  if (!invoiceId) {
    throw new PayPalApiError('PayPal Create Draft Invoice returned no invoice ID.', 502);
  }

  const qrRes = await fetch(
    `${baseUrl}/v2/invoicing/invoices/${encodeURIComponent(invoiceId)}/qr-code`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ width: 300, height: 300, action: 'pay' }),
      signal: AbortSignal.timeout(PAYPAL_TIMEOUT_MS),
    }
  );
  const qrParsed = await parsePayPalResponse(
    qrRes,
    `Generate Invoice QR (POST /v2/invoicing/invoices/${invoiceId}/qr-code)`
  );
  const qrBase64Png =
    typeof qrParsed.data === 'string'
      ? qrParsed.data.replace(/"/g, '').trim()
      : qrParsed.data?.rawText?.replace(/"/g, '').trim() || null;

  return {
    invoiceId,
    invoiceNumber,
    qrBase64Png,
    debugId: draftParsed.debugId,
  };
}
