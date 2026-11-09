/**
 * Payegis Studio v3.5 — AI Procurement Agent, Channel3 Enrichment Validator &
 * Guarded PayPal Agent Toolkit Executor
 * Canonical Module: `./ai-procurement-agent.mjs`
 *
 * Implements Phase 4 & Finding #6 Fixes:
 * - AI financial tools (`executeGuardedAgentTool`) NEVER accept a bare `humanApproved: true` boolean;
 *   every mutating financial tool requires a cryptographically bound `approvalRecord` verified via `verifyBoundApprovalRecord()`.
 * - In Live Mode (`LIVE_PAYPAL_SANDBOX` / `LIVE_PAYPAL_PRODUCTION`), AI tools NEVER directly mutate local FSM state;
 *   they route through the authoritative PayPal execution layer (`paypal-core.mjs`), validate preconditions on a clone first,
 *   and only commit state after authoritative PayPal response verification.
 * - Channel3 enrichment strictly validates score ranges and never overwrites authoritative financial prices or fulfillment hashes.
 */

import {
  DEFAULT_LINE_ITEMS,
  evaluateProcurementPolicy,
  recordOrderCreatedAwaitingBuyer,
  approveHumanGateAndAuthorize,
  reauthorizeEscrowHold,
  executePartialCapture,
  voidRemainingAuthorization,
  executeVendorSplitPayout,
  submitDisputeEvidence,
  verifyBoundApprovalRecord,
  usdToCents,
} from './fsm-and-policy.mjs';

import {
  resolvePayPalEnvironment,
  liveCreateOrder,
  liveAuthorizeApprovedOrder,
  liveReauthorizeHold,
  livePartialCapture,
  liveVoidAuthorization,
  liveCreateVendorSplitPayout,
  liveProvideDisputeEvidence,
} from './paypal-core.mjs';

const CHANNEL3_BASE_URL = process.env.CHANNEL3_BASE_URL || 'https://api.trychannel3.com/v0';
const EXTERNAL_API_TIMEOUT_MS = 10000;

export function hasLiveChannel3Key() {
  const key = (process.env.CHANNEL3_API_KEY || '').trim();
  return Boolean(key) && key !== 'your_channel3_api_key_here';
}

export function hasLiveAiModelKey() {
  const key = (process.env.AI_API_KEY || process.env.OPENAI_API_KEY || '').trim();
  return Boolean(key) && !key.startsWith('your_');
}

export function validateChannel3Items(items, authoritativeItems = null) {
  if (!Array.isArray(items) || items.length === 0) {
    const err = new Error('CHANNEL3_INVALID_RESPONSE: Items array is empty or missing.');
    err.statusCode = 502;
    err.code = 'CHANNEL3_INVALID_RESPONSE';
    throw err;
  }

  const authMap = new Map(
    (authoritativeItems || []).map((a) => [String(a.sku || '').trim(), a])
  );

  return items.map((item) => {
    const sku = String(item?.sku || '').trim();
    const score = Number(item?.channel3Score);
    const authItem = authMap.get(sku);
    const totalUsd = Number(authItem ? authItem.totalUsd : item?.totalUsd);
    const unitPriceUsd = Number(authItem ? authItem.unitPriceUsd : item?.unitPriceUsd ?? totalUsd);
    const quantity = Number(authItem ? authItem.quantity : item?.quantity ?? 1);

    if (
      !sku ||
      !Number.isFinite(score) ||
      score < 0 ||
      score > 100 ||
      !Number.isFinite(totalUsd) ||
      totalUsd <= 0
    ) {
      const err = new Error(
        `CHANNEL3_SCHEMA_VALIDATION_FAILED: Invalid trust score or price on SKU ${
          sku || 'UNKNOWN'
        }.`
      );
      err.statusCode = 502;
      err.code = 'CHANNEL3_SCHEMA_VALIDATION_FAILED';
      throw err;
    }

    // Channel3 enrichment can supply merchant trust score, but must NEVER overwrite authoritative price or fulfillment proof
    return {
      ...(authItem || item),
      sku,
      channel3Score: score,
      totalUsd,
      unitPriceUsd,
      quantity,
      deliveryStatus: authItem ? authItem.deliveryStatus : item.deliveryStatus,
      fulfillmentSha256: authItem ? authItem.fulfillmentSha256 : item.fulfillmentSha256,
    };
  });
}

export async function enrichProcurementBundleWithChannel3(requestedItems = DEFAULT_LINE_ITEMS) {
  const validatedFixtures = validateChannel3Items(requestedItems);
  if (!hasLiveChannel3Key()) {
    return {
      source: 'SANDBOX_FIXTURE_DEMO_DATA',
      liveApiCalled: false,
      enrichedAt: new Date().toISOString(),
      items: validatedFixtures.map((item) => ({
        ...item,
        dataOrigin: 'SANDBOX_FIXTURE_DEMO_DATA',
      })),
    };
  }

  const res = await fetch(`${CHANNEL3_BASE_URL}/enrich`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.CHANNEL3_API_KEY.trim()}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      items: validatedFixtures.map((i) => ({
        sku: i.sku,
        name: i.name,
        vendorName: i.vendorName,
        unitPriceUsd: i.unitPriceUsd,
      })),
    }),
    signal: AbortSignal.timeout(EXTERNAL_API_TIMEOUT_MS),
  });

  if (!res.ok) {
    const err = new Error(`CHANNEL3_API_ERROR: Upstream returned HTTP ${res.status}`);
    err.statusCode = 502;
    err.code = 'CHANNEL3_API_ERROR';
    throw err;
  }

  const data = await res.json();
  const validatedLiveItems = validateChannel3Items(data?.items, validatedFixtures);
  return {
    source: 'LIVE_CHANNEL3_API',
    liveApiCalled: true,
    enrichedAt: new Date().toISOString(),
    items: validatedLiveItems.map((item) => ({
      ...item,
      dataOrigin: 'LIVE_CHANNEL3_API',
    })),
  };
}

export async function getGuardedPayPalAgentToolkitManifest() {
  let toolkitAvailable = false;
  try {
    await import('@paypal/agent-toolkit');
    toolkitAvailable = true;
  } catch (_) {
    toolkitAvailable = false;
  }

  return {
    package: '@paypal/agent-toolkit@1.0.2',
    sdkModuleInstalled: toolkitAvailable,
    executionModel: 'SERVER_GUARDED_TOOL_EXECUTOR',
    enforcedGuardrail: 'STAGEPAY_HUMAN_GATE_AND_PROMPT_INJECTION_SHIELD',
    tools: [
      {
        name: 'paypal_evaluate_procurement_bundle',
        upstreamToolkitTool: 'orders.validate',
        mutatesFunds: false,
        description:
          'Evaluates a procurement bundle against deterministic budget and Channel3 rules.',
      },
      {
        name: 'paypal_create_escrow_order',
        upstreamToolkitTool: 'orders.create',
        mutatesFunds: true,
        forcedIntent: 'AUTHORIZE',
        requiresHumanApprovalAboveUsd: 250.0,
        description:
          'Creates a PayPal Orders v2 AUTHORIZE hold only after bound human approval record is verified.',
      },
      {
        name: 'paypal_authorize_order',
        upstreamToolkitTool: 'orders.authorize',
        mutatesFunds: true,
        description: 'Authorizes a buyer-approved PayPal Order.',
      },
      {
        name: 'paypal_reauthorize_hold',
        upstreamToolkitTool: 'payments.reauthorizeAuthorization',
        mutatesFunds: true,
        description: 'Reauthorizes an active authorization hold after the 72h honor period.',
      },
      {
        name: 'paypal_partial_capture_tranche',
        upstreamToolkitTool: 'payments.captureAuthorization',
        mutatesFunds: true,
        requiresVerifiedSha256Delivery: true,
        description:
          'Partially captures only delivered vendor line items (final_capture: false).',
      },
      {
        name: 'paypal_void_uncaptured_remainder',
        upstreamToolkitTool: 'payments.voidAuthorization',
        mutatesFunds: true,
        description: 'Releases uncaptured authorization hold when a vendor breaches SLA.',
      },
      {
        name: 'paypal_disburse_vendor_split_payout',
        upstreamToolkitTool: 'payouts.create',
        mutatesFunds: true,
        description:
          'Disburses captured funds across verified delivered vendors via PayPal Payouts v1.',
      },
      {
        name: 'paypal_get_transaction_status',
        upstreamToolkitTool: 'orders.get',
        mutatesFunds: false,
        description: 'Returns the authoritative transaction state and balances.',
      },
      {
        name: 'paypal_get_payout_status',
        upstreamToolkitTool: 'payouts.get',
        mutatesFunds: false,
        description: 'Returns the current payout batch status and item breakdown.',
      },
      {
        name: 'paypal_submit_dispute_evidence',
        upstreamToolkitTool: 'disputes.provideEvidence',
        mutatesFunds: false,
        description: 'Submits carrier tracking and SHA-256 fulfillment proof to a dispute.',
      },
    ],
  };
}

function assertBoundApprovalForAgentTool(toolName, toolArgs, session, expectedAmountUsd = null) {
  const check = verifyBoundApprovalRecord(toolArgs.approvalRecord, {
    sessionId: session?.sessionId,
    operation: toolName,
    expectedAmountUsd,
    expectedCurrency: 'USD',
  });
  if (!check.valid) {
    const err = new Error(
      `AGENT_TOOL_APPROVAL_RECORD_INVALID: Tool ${toolName} requires a bound approvalRecord (${check.reason}). Bare humanApproved booleans cannot authorize AI financial mutations.`
    );
    err.statusCode = 403;
    err.code = toolArgs.approvalRecord
      ? 'AGENT_TOOL_APPROVAL_RECORD_INVALID'
      : 'AGENT_TOOL_HUMAN_GATE_REQUIRED';
    throw err;
  }
  return check;
}

/**
 * Finding #6 Fix:
 * - Asynchronous guarded tool executor (`executeGuardedAgentTool`).
 * - Rejects bare `humanApproved: true` booleans; requires a cryptographically bound `approvalRecord` on mutating tools.
 * - Never directly mutates local FSM state in Live Mode (`LIVE_PAYPAL_*`); routes through the authoritative PayPal API layer (`paypal-core.mjs`) first!
 */
export async function executeGuardedAgentTool(toolName, toolArgs = {}, session) {
  if (toolName === 'paypal_evaluate_procurement_bundle') {
    return evaluateProcurementPolicy(toolArgs);
  }

  if (toolName === 'paypal_get_transaction_status') {
    return {
      sessionId: session.sessionId,
      state: session.state,
      orderId: session.orderId,
      authorizationId: session.authorizationId,
      activeAuthorizedHoldUsd: session.activeAuthorizedHoldUsd,
      capturedTotalUsd: session.capturedTotalUsd,
      voidedRemainderUsd: session.voidedRemainderUsd,
    };
  }

  if (toolName === 'paypal_get_payout_status') {
    return {
      payoutBatchId: session.payoutBatchId,
      payoutBatchStatus: session.payoutBatchStatus,
      payoutSplitTotalUsd: session.payoutSplitTotalUsd,
      items: session.payoutItems,
    };
  }

  const envInfo = resolvePayPalEnvironment();
  const isLiveSession = Boolean(session?.mode && session.mode.startsWith('LIVE_PAYPAL'));
  if (isLiveSession && !envInfo.hasCredentials) {
    const err = new Error(
      'LIVE_AI_TOOL_REQUIRES_PAYPAL_EXECUTION: AI financial tools cannot mutate local FSM state directly when session is in LIVE_PAYPAL mode without authoritative PayPal API credentials.'
    );
    err.statusCode = 502;
    err.code = 'LIVE_AI_TOOL_REQUIRES_PAYPAL_EXECUTION';
    throw err;
  }
  const useLivePayPal = isLiveSession || envInfo.hasCredentials;
  const requestId = toolArgs.requestId || `REQ-AGENT-${toolName.toUpperCase()}-${Date.now()}`;

  if (toolName === 'paypal_create_escrow_order') {
    const requestedTotal = toolArgs.totalUsd ?? session.proposedTotalUsd;
    const policyEval = evaluateProcurementPolicy({
      description: toolArgs.description || 'Agent order request',
      intent: toolArgs.intent || 'AUTHORIZE',
      totalUsd: requestedTotal,
      currency: toolArgs.currency || 'USD',
      items: toolArgs.items || session.items,
    });
    if (!policyEval.allowed) {
      const err = new Error(`AGENT_TOOL_POLICY_BLOCKED: ${policyEval.reasons.join(' | ')}`);
      err.statusCode = 422;
      err.code = 'AGENT_TOOL_POLICY_BLOCKED';
      throw err;
    }

    if (policyEval.requiresHumanGate) {
      assertBoundApprovalForAgentTool(toolName, toolArgs, session, requestedTotal);
    }

    if (useLivePayPal) {
      const liveOrder = await liveCreateOrder({
        requestId,
        invoiceNumber: session.invoiceNumber,
        totalUsd: requestedTotal,
        description: toolArgs.description || 'Payegis Guarded AI Agent Order',
      });
      if (toolArgs.requireBuyerRedirect !== false) {
        return recordOrderCreatedAwaitingBuyer(session, {
          requestId,
          approver: toolArgs.approvalRecord?.approver,
          orderId: liveOrder.orderId,
          buyerApprovalUrl: liveOrder.approveLink,
        });
      }
      const liveAuth = await liveAuthorizeApprovedOrder({
        orderId: liveOrder.orderId,
        requestId: `${requestId}-AUTH`,
      });
      return approveHumanGateAndAuthorize(session, {
        requestId,
        approver: toolArgs.approvalRecord?.approver,
        orderId: liveAuth.orderId,
        authorizationId: liveAuth.authorizationId,
        buyerApprovalUrl: liveOrder.approveLink,
        requireRealIds: true,
      });
    }

    if (toolArgs.requireBuyerRedirect) {
      return recordOrderCreatedAwaitingBuyer(session, {
        requestId,
        approver: toolArgs.approvalRecord?.approver || 'Human Approver (via Guarded Agent Tool)',
        orderId: toolArgs.orderId || '5O190127TN364715T',
      });
    }

    return approveHumanGateAndAuthorize(session, {
      requestId,
      approver: toolArgs.approvalRecord?.approver || 'Human Approver (via Guarded Agent Tool)',
    });
  }

  if (toolName === 'paypal_authorize_order') {
    assertBoundApprovalForAgentTool(toolName, toolArgs, session, session.authorizedTotalUsd);
    if (useLivePayPal) {
      const liveAuth = await liveAuthorizeApprovedOrder({
        orderId: toolArgs.orderId || session.orderId,
        requestId,
      });
      return approveHumanGateAndAuthorize(session, {
        requestId,
        orderId: liveAuth.orderId,
        authorizationId: liveAuth.authorizationId,
        requireRealIds: true,
      });
    }
    return approveHumanGateAndAuthorize(session, {
      requestId,
      orderId: toolArgs.orderId || session.orderId,
      authorizationId: toolArgs.authorizationId,
    });
  }

  if (toolName === 'paypal_reauthorize_hold') {
    assertBoundApprovalForAgentTool(toolName, toolArgs, session, session.authorizedTotalUsd);
    const preview = structuredClone(session);
    reauthorizeEscrowHold(preview, { requestId, enforceClockGate: true });
    let liveReauth = null;
    if (useLivePayPal) {
      liveReauth = await liveReauthorizeHold({
        authorizationId: session.authorizationId,
        amountUsd: session.authorizedTotalUsd,
        requestId,
      });
    }
    return reauthorizeEscrowHold(session, {
      requestId,
      newAuthorizationId: liveReauth?.newAuthorizationId || toolArgs.newAuthorizationId,
      enforceClockGate: true,
    });
  }

  if (toolName === 'paypal_partial_capture_tranche') {
    const preview = structuredClone(session);
    const previewCap = executePartialCapture(preview, {
      requestId,
      skus: toolArgs.skus,
      artifactPayloads: toolArgs.artifactPayloads,
      captureStatus: 'COMPLETED',
    });
    assertBoundApprovalForAgentTool(toolName, toolArgs, session, previewCap.result.amountUsd);

    let liveCapture = null;
    if (useLivePayPal) {
      liveCapture = await livePartialCapture({
        authorizationId: session.authorizationId,
        amountUsd: previewCap.result.amountUsd,
        invoiceNumber: session.invoiceNumber,
        finalCapture: previewCap.result.finalCapture,
        requestId,
      });
    }
    return executePartialCapture(session, {
      requestId,
      skus: toolArgs.skus,
      artifactPayloads: toolArgs.artifactPayloads,
      isLiveMode: useLivePayPal,
      captureId: liveCapture?.captureId || toolArgs.captureId,
      captureStatus: liveCapture?.status || toolArgs.captureStatus || 'COMPLETED',
    });
  }

  if (toolName === 'paypal_void_uncaptured_remainder') {
    const preview = structuredClone(session);
    const previewVoid = voidRemainingAuthorization(preview, {
      requestId,
      requirePartialCaptureFirst: true,
    });
    assertBoundApprovalForAgentTool(toolName, toolArgs, session, previewVoid.result.voidedAmountUsd);

    if (useLivePayPal) {
      await liveVoidAuthorization({
        authorizationId: session.authorizationId,
        requestId,
      });
    }
    return voidRemainingAuthorization(session, {
      requestId,
      requirePartialCaptureFirst: true,
    });
  }

  if (toolName === 'paypal_disburse_vendor_split_payout') {
    const preview = structuredClone(session);
    const previewPayout = executeVendorSplitPayout(preview, {
      requestId,
      isLiveMode: useLivePayPal,
      requireRemainderResolvedFirst: true,
    });
    assertBoundApprovalForAgentTool(toolName, toolArgs, session, session.capturedTotalUsd);

    let livePayout = null;
    if (useLivePayPal) {
      livePayout = await liveCreateVendorSplitPayout({
        sessionId: session.sessionId,
        items: previewPayout.result.items,
        requestId,
      });
    }
    return executeVendorSplitPayout(session, {
      requestId,
      isLiveMode: useLivePayPal,
      requireRemainderResolvedFirst: true,
      payoutBatchId: livePayout?.payoutBatchId || toolArgs.payoutBatchId,
      batchStatus: livePayout?.batchStatus || toolArgs.batchStatus,
      itemStatuses: livePayout?.itemStatuses || toolArgs.itemStatuses,
      witnessVerified: Boolean(livePayout?.witnessVerified),
    });
  }

  if (toolName === 'paypal_submit_dispute_evidence') {
    const preview = structuredClone(session);
    const previewDisp = submitDisputeEvidence(preview, {
      requestId,
      disputeId: toolArgs.disputeId,
      isLiveMode: useLivePayPal,
      requirePayoutCompletedFirst: true,
    });
    let liveDispute = null;
    if (useLivePayPal) {
      liveDispute = await liveProvideDisputeEvidence({
        disputeId: toolArgs.disputeId,
        evidences: previewDisp.result.evidences,
        requestId,
      });
    }
    return submitDisputeEvidence(session, {
      requestId,
      disputeId: toolArgs.disputeId,
      isLiveMode: useLivePayPal,
      requirePayoutCompletedFirst: true,
      preSubmissionDisputeStatus: liveDispute?.preSubmissionStatus,
      disputeStatus: liveDispute?.status || 'UNDER_REVIEW',
    });
  }

  const err = new Error(`UNKNOWN_AGENT_TOOL: Tool ${toolName} is not registered.`);
  err.statusCode = 400;
  err.code = 'UNKNOWN_AGENT_TOOL';
  throw err;
}

export async function runAiProcurementAgent({
  userPrompt = 'Source 3 cloud AI infrastructure tranches (GPU cluster, SERP API quota, compliance dataset) under $1,500 cap and evaluate fulfillment SLA.',
  items = DEFAULT_LINE_ITEMS,
} = {}) {
  const safePrompt = String(userPrompt || '').slice(0, 2000);
  const enrichment = await enrichProcurementBundleWithChannel3(items);
  const totalUsd = Number(
    enrichment.items.reduce((sum, i) => sum + Number(i.totalUsd), 0).toFixed(2)
  );

  const policyCheck = evaluateProcurementPolicy({
    description: safePrompt,
    intent: 'AUTHORIZE',
    totalUsd,
    currency: 'USD',
    items: enrichment.items,
  });

  const deliveredItems = enrichment.items.filter(
    (i) => i.deliveryStatus === 'DELIVERED_VERIFIED'
  );
  const breachedItems = enrichment.items.filter(
    (i) => i.deliveryStatus !== 'DELIVERED_VERIFIED'
  );
  const recommendedCaptureUsd = Number(
    deliveredItems.reduce((sum, i) => sum + Number(i.totalUsd), 0).toFixed(2)
  );
  const recommendedVoidUsd = Number(
    breachedItems.reduce((sum, i) => sum + Number(i.totalUsd), 0).toFixed(2)
  );

  let llmExplanation = null;
  let engineMode = 'DETERMINISTIC_NEURO_SYMBOLIC_FALLBACK';
  let providerWarning = null;

  if (hasLiveAiModelKey() && policyCheck.allowed) {
    try {
      const apiKey = (process.env.AI_API_KEY || process.env.OPENAI_API_KEY).trim();
      const baseUrl = (process.env.AI_BASE_URL || 'https://api.openai.com/v1').replace(/\/+$/, '');
      const model = process.env.AI_MODEL || 'gpt-4o-mini';

      const res = await fetch(`${baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model,
          temperature: 0,
          max_tokens: 400,
          response_format: { type: 'json_object' },
          messages: [
            {
              role: 'system',
              content:
                'You are the Payegis Studio Financial Control Plane AI Auditor. Return a JSON object with a single string key "summary" explaining why the delivered items qualify for partial capture and the SLA-breached item qualifies for void release. You cannot alter dollar amounts or bypass human approval.',
            },
            {
              role: 'user',
              content: JSON.stringify({
                totalUsd,
                recommendedCaptureUsd,
                recommendedVoidUsd,
              }),
            },
          ],
        }),
        signal: AbortSignal.timeout(EXTERNAL_API_TIMEOUT_MS),
      });

      if (res.ok) {
        const data = await res.json();
        const rawContent = data?.choices?.[0]?.message?.content;
        if (rawContent) {
          const parsed = JSON.parse(rawContent);
          if (typeof parsed?.summary === 'string' && parsed.summary.trim().length > 0) {
            llmExplanation = parsed.summary.trim().slice(0, 1000);
            engineMode = `LIVE_LLM_API (${model})`;
          }
        }
      } else {
        providerWarning = `LLM provider returned HTTP ${res.status}; fell back to deterministic reasoner.`;
      }
    } catch (err) {
      providerWarning = `LLM provider unreachable or returned invalid JSON (${err.message}); fell back to deterministic reasoner.`;
    }
  }

  return {
    engineMode,
    channel3DataSource: enrichment.source,
    providerWarning,
    evaluatedAt: new Date().toISOString(),
    userPrompt: safePrompt,
    policyEvaluation: policyCheck,
    deliberation: {
      summary:
        llmExplanation ||
        (policyCheck.allowed
          ? `Bundle ($${totalUsd.toFixed(
              2
            )} USD) passed 20-rule prompt-injection and Channel3 trust checks (>=85.0). Routed to PENDING_HUMAN_GATE (>=$250 threshold). Post-authorization SLA audit verified ${
              deliveredItems.length
            }/${enrichment.items.length} tranches delivered ($${recommendedCaptureUsd.toFixed(
              2
            )} capture) and flagged ${
              breachedItems.length
            } SLA breach ($${recommendedVoidUsd.toFixed(2)} uncaptured hold release).`
          : `Blocked by deterministic policy guard: ${policyCheck.reasons.join(' | ')}`),
      enforcedIntent: 'AUTHORIZE',
      requiresHumanGate: policyCheck.requiresHumanGate,
      recommendedHoldUsd: policyCheck.allowed ? totalUsd : 0,
      recommendedPartialCaptureUsd: policyCheck.allowed ? recommendedCaptureUsd : 0,
      recommendedVoidRemainderUsd: policyCheck.allowed ? recommendedVoidUsd : 0,
      trancheBreakdown: enrichment.items.map((i) => ({
        sku: i.sku,
        vendorName: i.vendorName,
        amountUsd: i.totalUsd,
        channel3Score: i.channel3Score,
        deliveryStatus: i.deliveryStatus,
        decision:
          i.deliveryStatus === 'DELIVERED_VERIFIED'
            ? 'CAPTURE_AND_DISBURSE'
            : 'VOID_UNCAPTURED_HOLD',
      })),
    },
  };
}
