import { describe, expect, test, vi } from 'vitest';
import request from 'supertest';
import express from 'express';
import { create } from '../../../src/v2/frameworks/express.js';
import { deriveKey } from '../../../src/v2/algorithms/pbkdf2.js';
import { createChallenge, solveChallenge } from '../../../src/v2/pow.js';

function jsonResponse(status: number, data: unknown) {
	return new Response(JSON.stringify(data), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
}

describe('Express', () => {
	const hmacSignatureSecret = 'secret.key';

	describe('create()', () => {
		test('should return an object with app and middleware', () => {
			const result = create({
				createChallengeParameters() {
					return {
						algorithm: 'PBKDF2/SHA-256',
						cost: 10,
						counter: 10,
					};
				},
				deriveKey,
				hmacSignatureSecret,
			});
			expect(result.challengeHandler).toBeTypeOf('function');
			expect(result.verifyHandler).toBeTypeOf('function');
			expect(result.middleware).toBeTypeOf('function');
			expect(result.verify).toBeTypeOf('function');
		});
	});

	describe('handlers', () => {
		const altcha = create({
			createChallengeParameters() {
				return {
					algorithm: 'PBKDF2/SHA-256',
					cost: 10,
					counter: 10,
				};
			},
			deriveKey,
			hmacSignatureSecret,
		});

		async function createPayload(
			options?: Partial<Parameters<typeof createChallenge>[0]>
		) {
			const challenge = await createChallenge({
				algorithm: 'PBKDF2/SHA-256',
				cost: 10,
				counter: 10,
				deriveKey,
				hmacSignatureSecret,
				...options,
			});
			const solution = await solveChallenge({
				challenge,
				deriveKey,
			});
			const payload = btoa(
				JSON.stringify({
					challenge,
					solution,
				})
			);
			return {
				challenge,
				payload,
				solution,
			};
		}

		describe('routes', () => {
			describe('/challenge', () => {
				test('should return a new challenge', async () => {
					const app = express();
					app.use(express.json());
					app.get('/challenge', altcha.challengeHandler);
					const res = await request(app).get('/challenge');
					const json = res.body;
					expect(json.parameters).toBeDefined();
					expect(json.parameters.algorithm).toBeDefined();
					expect(json.parameters.cost).toBeDefined();
					expect(json.parameters.nonce).toBeDefined();
					expect(json.parameters.salt).toBeDefined();
					expect(json.signature).toBeDefined();
				});
			});

			describe('/verify', () => {
				test('should verify the payload and return the result', async () => {
					const { challenge, payload, solution } = await createPayload();
					const app = express();
					app.use(express.json());
					app.post('/verify', altcha.verifyHandler);
					const res = await request(app).post('/verify').send({
						altcha: payload,
					});
					const json = res.body;
					expect(json).toEqual({
						error: null,
						payload: {
							challenge,
							solution,
						},
						verification: {
							expired: false,
							invalidSignature: false,
							invalidSolution: false,
							time: expect.any(Number),
							verified: true,
						},
					});
				});
			});
		});

		describe('middleware', () => {
			function createApp() {
				const app = express();
				app.use(express.json());
				app.use(express.urlencoded({ extended: true }));
				app.post('/submit', altcha.middleware(), (req, res) => {
					res.json({
						success: true,
					});
				});
				return app;
			}

			test('should pass with a valid payload', async () => {
				const app = createApp();
				const { payload } = await createPayload();
				const res = await request(app)
					.post('/submit')
					.send(`altcha=${encodeURIComponent(payload)}`);
				const json = res.body;
				expect(json).toEqual({
					success: true,
				});
			});

			test('should throw error if challenge expired', async () => {
				const app = createApp();
				const { payload } = await createPayload({
					expiresAt: new Date(Date.now() - 1_000),
				});
				const body = new FormData();
				body.set('test', 'test');
				body.set('altcha', payload);
				const res = await request(app)
					.post('/submit')
					.send(`altcha=${encodeURIComponent(payload)}`);
				expect(res.text.includes('ALTCHA verification failed')).toBeTruthy();
			});

			test('should throw error if payload is missing', async () => {
				const app = createApp();
				const res = await request(app).post('/submit').send(`test=test`);
				expect(res.text.includes('ALTCHA payload is missing')).toBeTruthy();
			});
		});

		describe('remote verification (verifyServer)', () => {
			test('should verify a Sentinel-issued payload via the remote API', async () => {
				const remoteResult = {
					apiKey: 'key_1',
					verificationData: { verified: true },
					verified: true,
				};
				const fetchMock = vi
					.fn()
					.mockResolvedValue(jsonResponse(200, remoteResult));
				const remoteAltcha = create({
					verifyServer: {
						fetch: fetchMock,
						url: 'https://sentinel.example.com/v1/verify/signature',
					},
				});
				const sentinelPayload = btoa(
					JSON.stringify({
						algorithm: 'SHA-256',
						id: 'chl_1',
						signature: 'sig',
						verificationData: 'verified=1',
						verified: true,
					})
				);
				const app = express();
				app.use(express.json());
				app.post('/verify', remoteAltcha.verifyHandler);
				const res = await request(app).post('/verify').send({
					altcha: sentinelPayload,
				});
				expect(res.body.verification).toEqual(remoteResult);
				expect(fetchMock).toHaveBeenCalledTimes(1);
			});

			test('challengeHandler should fail clearly without deriveKey/createChallengeParameters', async () => {
				const remoteAltcha = create({
					verifyServer: {
						url: 'https://sentinel.example.com/v1/verify/signature',
					},
				});
				const app = express();
				app.get('/challenge', remoteAltcha.challengeHandler);
				const res = await request(app).get('/challenge');
				expect(res.status).toBe(500);
			});
		});
	});
});
