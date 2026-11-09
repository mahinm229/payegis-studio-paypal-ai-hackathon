# APIMatic SDK Generation, Validation & Zero-Retry Financial Safety in Payegis Studio

## 1. How APIMatic Powers `@paypal/paypal-server-sdk@2.5.0` in Payegis Studio

PayPal's official TypeScript/JavaScript Server SDK ([`@paypal/paypal-server-sdk@2.5.0`](https://www.npmjs.com/package/@paypal/paypal-server-sdk) on NPM, source at [`paypal/PayPal-TypeScript-Server-SDK`](https://github.com/paypal/PayPal-TypeScript-Server-SDK)) is generated using **[APIMatic CodeGen v3.0](https://www.apimatic.io/)**. In [`paypal-core.mjs`](paypal-core.mjs), `getPayPalServerSdkSingleton()` initializes a cached APIMatic `Client` singleton with zero automatic mutation retries (`retryConfig: { maxNumberOfRetries: 0, retryOnTimeout: false }`):

```javascript
const client = new sdk.Client({
  clientCredentialsAuthCredentials: {
    oAuthClientId: env.clientId,
    oAuthClientSecret: env.clientSecret,
  },
  timeout: 15000,
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
```

When a socket timeout occurs during an authorization or capture request, Payegis never fires blind background retries; instead, it records the timeout in the durable operation journal (`persistence-store.mjs`), transitions the session to `UNKNOWN_TIMEOUT`, and reconciles against PayPal's authoritative `GET` witness endpoint (`reconcileUnknownTimeout()`).
