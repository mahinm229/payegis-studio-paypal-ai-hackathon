# Payegis Studio v3.5 — The Financial Control Plane for Autonomous Commerce on PayPal

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![PayPal Server SDK](https://img.shields.io/badge/%40paypal%2Fpaypal--server--sdk-2.5.0-0070ba.svg)](https://www.npmjs.com/package/@paypal/paypal-server-sdk)
[![PayPal Agent Toolkit](https://img.shields.io/badge/%40paypal%2Fagent--toolkit-1.0.2-003087.svg)](https://www.npmjs.com/package/@paypal/agent-toolkit)
[![Automated Test Suites](https://img.shields.io/badge/Automated_Tests-55%2F55_Passing-10b981.svg)](payegis.test.mjs)
[![Adversarial & FSM Benchmark](https://img.shields.io/badge/Security_&_FSM_Benchmark-20%2F20_Passing-10b981.svg)](fsm-and-policy.mjs)

> **AI agents can propose. Deterministic policies can validate. Humans can authorize. PayPal can execute. Payegis verifies and reconciles.**  
> **Payegis Studio v3.5** is an AI procurement governance, payment authorization, fulfillment verification, and multi-vendor settlement orchestration platform built on the [PayPal Developer Platform](https://developer.paypal.com/). Rather than acting as a regulated third-party escrow bank or letting autonomous agents execute raw `intent: "CAPTURE"` calls, Payegis orchestrates **PayPal Orders v2 (`AUTHORIZE` + buyer approval + `/authorize`)**, **Payments v2 (`reauthorize`, partial `capture` with `final_capture: false`, and uncaptured hold release via `void`)**, **Payouts v1**, **Disputes v1 (`provide-evidence`)**, and **Invoices v2 (`qr-code`)** behind a durable checkpoint, an append-only operation journal, and a SHA-256 tamper-evident audit chain.

---

## 1. Transparent Dual-Mode Execution (Fail-Closed Live PayPal Sandbox + Labelled Offline Simulator)

| Execution Mode | When Active | What Happens |
| :--- | :--- | :--- |
| **Live PayPal Sandbox API Mode (`LIVE_PAYPAL_SANDBOX`)** | When `server.mjs` is running (`npm start`) with `PAYPAL_CLIENT_ID` and `PAYPAL_CLIENT_SECRET` configured in `.env` | Every UI action invokes `fetch('/api/escrow/...')` against `server.mjs`, which executes live REST & SDK calls against `https://api-m.sandbox.paypal.com` across all 10 lifecycle functions in [`paypal-core.mjs`](paypal-core.mjs). If PayPal returns any HTTP 4xx/5xx error, Payegis **fails closed** (it never masks a live API error with a simulator fallback). |
| **Labelled Offline Simulator Mode (`OFFLINE_SIMULATOR`)** | When opened on static GitHub Pages (`https://mahinm229.github.io/payegis-studio-paypal-ai-hackathon/`) or without `.env` keys | The header displays `MODE: LABELLED OFFLINE SIMULATOR` and executes the deterministic Finite State Machine ([`fsm-and-policy.mjs`](fsm-and-policy.mjs)) using clearly tagged `[FIXTURE]` data. |

---

## 2. 60-Second Quickstart & Verification Commands

```bash
# 1. Clone the repository
git clone https://github.com/mahinm229/payegis-studio-paypal-ai-hackathon.git
cd payegis-studio-paypal-ai-hackathon

# 2. Run the 55-Suite Automated Verification, Security, QR Decode & Mocked PayPal Tests
npm test

# 3. Run the Live 20-Case Adversarial Prompt-Injection, Base64 Obfuscation & FSM Benchmark
npm run benchmark

# 4. Start the Full-Stack HTTP Control Plane (defaults to http://localhost:8787)
cp .env.example .env
# Optional: Add PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, CHANNEL3_API_KEY, AI_API_KEY in .env
npm start
```

---

## 3. Canonical Repository Architecture

All modules reside in a single canonical root layout so standard Git clones and GitHub web uploads resolve identically:

- [`index.html`](index.html) — Interactive Control Plane UI with 4 Judge Tours, strict sequential & temporal FSM gates, explanatory blocked-click banners + audit logging, multi-line wrapping AG Grid v32.3.3 vendor matrix, Chart.js settlement waterfall, multi-step reversible Sandbox Clock simulator, and multi-version ISO/IEC 18004 QR generator.
- [`server.mjs`](server.mjs) — HTTP Control Plane server with automatic `.env` loading, synchronous state initialization, exact Set-based CORS allowlist, operator token auth, 64KB body cap, bounded LRU rate limiter, PayPal webhook verification (`/api/webhooks/paypal`), and pre/post-flight operation journaling.
- [`fsm-and-policy.mjs`](fsm-and-policy.mjs) — Deterministic Finite State Machine, integer-cent math engine, SHA-256 fulfillment artifact verification, Base64/URL/Unicode prompt-injection decoder, SHA-256 tamper-evident hash chain, ISO/IEC 18004 QR encoder & decoder, and 20-case benchmark.
- [`paypal-core.mjs`](paypal-core.mjs) — Live PayPal Sandbox & `@paypal/paypal-server-sdk@2.5.0` integration (OAuth2 caching, Create Order, Order Witness, Authorize Order, Reauthorize, Partial Capture, Void Remainder, Payouts v1 Split, Disputes v1 Evidence, and Invoices v2 QR).
- [`ai-procurement-agent.mjs`](ai-procurement-agent.mjs) — Channel3 schema validator, live LLM deliberation client with deterministic override protection, and 10-tool guarded `@paypal/agent-toolkit` executor.
- [`persistence-store.mjs`](persistence-store.mjs) — PostgreSQL transactional checkpoint & operation journal store (`DATABASE_URL`) with optimistic version control (`STALE_SESSION_VERSION_CONFLICT`) + local atomic snapshot & append-only JSONL operation journal (`.payegis-data/`).
- [`payegis.test.mjs`](payegis.test.mjs) — 55 automated test suites (`55/55 passing`) covering policy, buyer approval, financial lifecycle, M1–M3 & L1–L3 UI/FSM regressions, QR round-trip decoding, mocked PayPal APIs, persistence recovery, optimistic locking, and webhook verification.
- [`Payegis_PayPal_v2.1.postman_collection.json`](Payegis_PayPal_v2.1.postman_collection.json) — 8-step chained Postman v2.1 collection.
- [`APIMATIC.md`](APIMATIC.md) — APIMatic SDK configuration and zero-retry timeout safety documentation.
