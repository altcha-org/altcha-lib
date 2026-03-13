import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { HTTPException } from 'hono/http-exception';
import { CappedMap, create, deriveHmacKeySecret, randomInt } from 'altcha-lib/frameworks/hono';
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2';

// Define your HMAC secret
const HMAC_SECRET = 'secret.key';

const altcha = create({
	// Verification HMAC secrets
	hmacSignatureSecret: HMAC_SECRET,
	hmacKeySignatureSecret: await deriveHmacKeySecret(HMAC_SECRET),
	// Adjust the challenge parameters using the createChallengeParameters function
	createChallengeParameters: () => {
		return {
			algorithm: 'PBKDF2/SHA-256',
			// Modify the cost and counter depending on the algorithm
			cost: 5_000,
			counter: randomInt(5_000, 10_000),
			expiresAt: new Date(Date.now() + 600_000), // 10 minutes
		};
	},
	// The key derivation function for the chosen algorithm
	deriveKey,
	// Instead of sending the payload in the form data, use cookie instead
	setCookie: {
		name: 'altcha',
		path: '/',
	},
	// For distributed environments, use Redis or similar to store used challenges
	store: new CappedMap<string, boolean>({
		maxSize: 1_000,
	}),
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

// Mount the /altcha/challenge and /altcha/verify routes
app.get('/altcha/challenge', altcha.challengeHandler);
app.post('/altcha/verify', altcha.verifyHandler);

// Mount the ALTCHA middleware for automatic verification
app.post('/submit', altcha.middleware(), async (c) => {
	const body = await c.req.parseBody();
	return c.json({
		altcha: c.var.altcha,
		body,
	});
});

export default app;
