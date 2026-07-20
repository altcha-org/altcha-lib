import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { HTTPException } from 'hono/http-exception';
import { create } from 'altcha-lib/frameworks/hono';

// URL of your ALTCHA Sentinel instance's verify/signature endpoint
const SENTINEL_URL = 'https://sentinel.example.com/v1/verify/signature';
// API key secret, optional — Sentinel checks it against the payload's API key
const SENTINEL_API_KEY_SECRET = 'sec_...';

const altcha = create({
	// No hmacSignatureSecret, deriveKey, or createChallengeParameters needed here —
	// Sentinel issues and signs challenges directly to the widget, this server only
	// verifies the resulting payload remotely.
	verifyServer: {
		url: SENTINEL_URL,
		secret: SENTINEL_API_KEY_SECRET,
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
