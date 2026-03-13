import { H3, defineEventHandler, readBody, handleCors } from 'h3';
import {
	CappedMap,
	create,
	deriveHmacKeySecret,
	randomInt,
} from 'altcha-lib/frameworks/h3';
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

const app = new H3();

// Enable CORS globally
app.use(
	defineEventHandler((event) => {
		const didHandleCors = handleCors(event, {
			origin: '*',
			methods: '*' as const,
			allowHeaders: ['Content-Type'],
			preflight: { statusCode: 204 },
		});
		if (didHandleCors) {
			// Preflight request was handled, return early
			return;
		}
	})
);

// ALTCHA routes
app.get('/altcha/challenge', altcha.challengeHandler);
app.post('/altcha/verify', altcha.verifyHandler);

// Protected route using middleware
const altchaMiddleware = altcha.middleware({ throwOnFailure: true });

app.post(
	'/submit',
	defineEventHandler(async (event) => {
		// Run ALTCHA verification first
		await altchaMiddleware(event);

		// If we get here, verification passed
		const body = await readBody(event);
		return {
			altcha: event.context.altcha,
			body,
		};
	})
);

export default app;
