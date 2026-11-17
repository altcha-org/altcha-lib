import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { HTTPException } from 'hono/http-exception';
import { create } from 'altcha-lib/frameworks/hono';

// URL of your ALTCHA Sentinel instance's verify/signature endpoint
const SENTINEL_URL = 'https://sentinel.example.com/v2/verify/signature';
// Restricted or full API key of the account that owns the widget's API key
const SENTINEL_API_KEY = { id: 'key_...', secret: 'sec_...' };

// Sentinel v1 instead: use the /v1 endpoint and replace `apiKey` below with the
// optional API key secret, `secret: 'sec_...'`.
// const SENTINEL_URL = 'https://sentinel.example.com/v1/verify/signature';

const altcha = create({
	// No hmacSignatureSecret, deriveKey, or createChallengeParameters needed here —
	// Sentinel issues and signs challenges directly to the widget, this server only
	// verifies the resulting payload remotely.
	verifyServer: {
		url: SENTINEL_URL,
		apiKey: SENTINEL_API_KEY,
		timeout: 10_000,
		retries: 2,
	},
	// No `store` needed either — Sentinel tracks used challenges itself and only
	// verifies a given payload once.
});

const app = new Hono();

app.use(cors());

app.onError((error, c) => {
	if (error instanceof HTTPException) {
		console.error(c.req.method, c.req.url, error.message);
		return error.getResponse();
	}
	return c.text('Internal Server Error.', 500);
});

// No /altcha/challenge route here — point the widget's `challengeurl` at your Sentinel
// instance instead, since it generates the challenges.

// Mount the ALTCHA middleware for automatic remote verification
app.post('/submit', altcha.middleware(), async (c) => {
	const body = await c.req.parseBody();
	return c.json({
		altcha: c.var.altcha,
		body,
	});
});

export default app;
