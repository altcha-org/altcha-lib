import Fastify from 'fastify';
import fastifyCors from '@fastify/cors';
import fastifyFormBody from '@fastify/formbody';
import { CappedMap, create, deriveHmacKeySecret, randomInt } from 'altcha-lib/frameworks/fastify';
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2';

// Define your HMAC secret
const HMAC_SECRET = 'secret.key';

// Server port number
const PORT = 3000;

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
	// setCookie: {
	// 	name: 'altcha',
	// 	path: '/',
	// },

	// For distributed environments, use Redis or similar to store used challenges
	store: new CappedMap<string, boolean>({
		maxSize: 1_000,
	}),
});

const app = Fastify({
	logger: true,
});

await app.register(fastifyCors);
await app.register(fastifyFormBody);

// Mount the /altcha/challenge and /altcha/verify routes
app.get('/altcha/challenge', altcha.challengeHandler);
app.post('/altcha/verify', altcha.verifyHandler);

// Mount the ALTCHA middleware as a preHandler for automatic verification
app.post(
	'/submit',
	{ preHandler: altcha.middleware() },
	async (request, reply) => {
		return reply.send({
			altcha: request.altcha,
			body: request.body,
		});
	}
);

// Start the fastify server
await app.listen({
	port: PORT
});
