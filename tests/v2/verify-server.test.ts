import { describe, expect, test, vi } from 'vitest';
import { verifyServer } from '../../src/v2/verify-server.js';

const URL_V1 = 'https://sentinel.example.com/v1/verify/signature';
const URL_V2 = 'https://sentinel.example.com/v2/verify/signature';

function jsonResponse(status: number, data: unknown) {
	return new Response(JSON.stringify(data), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
}

describe('Verify Server', () => {
	describe('verifyServer()', () => {
		test('should return successful verification result', async () => {
			const result = {
				apiKey: 'key_1',
				verificationData: { verified: true },
				verified: true,
			};
			const fetchMock = vi.fn().mockResolvedValue(jsonResponse(200, result));
			expect(
				await verifyServer({
					fetch: fetchMock,
					payload: 'payload',
					url: URL_V2,
				})
			).toEqual(result);
			expect(fetchMock).toHaveBeenCalledTimes(1);
		});

		test('should send apiKey as Basic credentials and only the payload in the body', async () => {
			const fetchMock = vi
				.fn()
				.mockResolvedValue(
					jsonResponse(200, { apiKey: 'key_1', verified: true })
				);
			await verifyServer({
				apiKey: { id: 'key_restricted', secret: 'sec_123' },
				fetch: fetchMock,
				payload: 'payload',
				secret: 'sec_ignored',
				url: URL_V2,
			});
			const [, init] = fetchMock.mock.calls[0];
			expect(init.headers.Authorization).toBe(
				`Basic ${btoa('key_restricted:sec_123')}`
			);
			expect(JSON.parse(init.body)).toEqual({ payload: 'payload' });
		});

		test('should send secret in the request body for a v1 Sentinel', async () => {
			const result = {
				apiKey: 'key_1',
				verificationData: null,
				verified: true,
			};
			const fetchMock = vi.fn().mockResolvedValue(jsonResponse(200, result));
			await verifyServer({
				fetch: fetchMock,
				payload: 'payload',
				secret: 'sec_123',
				url: URL_V1,
			});
			const [, init] = fetchMock.mock.calls[0];
			expect(init.headers.Authorization).toBeUndefined();
			expect(JSON.parse(init.body)).toEqual({
				payload: 'payload',
				secret: 'sec_123',
			});
		});

		test('should flatten nested v2 verificationData to the local shape', async () => {
			const fetchMock = vi.fn().mockResolvedValue(
				jsonResponse(200, {
					apiKey: 'key_1',
					verificationData: {
						device: { browser: 'Firefox', edk: '0123' },
						expire: 1700000000,
						fields: ['email', 'text'],
						params: { zip: '01234' },
						verified: true,
					},
					verified: true,
				})
			);
			const result = await verifyServer({
				fetch: fetchMock,
				payload: 'payload',
				url: URL_V2,
			});
			expect(result.verificationData).toEqual({
				'device.browser': 'Firefox',
				'device.edk': '0123',
				expire: 1700000000,
				fields: ['email', 'text'],
				'params.zip': '01234',
				verified: true,
			});
		});

		test('should return failed verification result if already used', async () => {
			const result = {
				apiKey: null,
				reason: 'PAYLOAD_ALREADY_USED',
				verificationData: null,
				verified: false,
			};
			const fetchMock = vi.fn().mockResolvedValue(jsonResponse(200, result));
			expect(
				await verifyServer({
					fetch: fetchMock,
					payload: 'payload',
					url: URL_V2,
				})
			).toEqual(result);
		});

		test('should not retry on 400 bad request from a v1 Sentinel', async () => {
			const fetchMock = vi
				.fn()
				.mockResolvedValue(
					jsonResponse(400, { error: 'INVALID_PAYLOAD', statusCode: 400 })
				);
			expect(
				await verifyServer({
					fetch: fetchMock,
					payload: 'payload',
					retries: 3,
					url: URL_V1,
				})
			).toEqual({
				reason: 'INVALID_PAYLOAD',
				verified: false,
			});
			expect(fetchMock).toHaveBeenCalledTimes(1);
		});

		test.each([401, 403, 429])(
			'should return the error code without retrying on %i',
			async (status) => {
				const fetchMock = vi.fn().mockResolvedValue(
					jsonResponse(status, {
						code: 'UNAUTHORIZED',
						error: 'Basic authentication requires a restricted or full-access API key.',
						statusCode: status,
					})
				);
				expect(
					await verifyServer({
						fetch: fetchMock,
						payload: 'payload',
						retries: 3,
						retryDelay: 1,
						url: URL_V2,
					})
				).toEqual({
					reason: 'UNAUTHORIZED',
					verified: false,
				});
				expect(fetchMock).toHaveBeenCalledTimes(1);
			}
		);

		test('should retry on 5xx and return the error code', async () => {
			const fetchMock = vi.fn().mockImplementation(async () =>
				jsonResponse(503, {
					code: 'UNAVAILABLE',
					error: 'Service unavailable.',
					statusCode: 503,
				})
			);
			expect(
				await verifyServer({
					fetch: fetchMock,
					payload: 'payload',
					retries: 2,
					retryDelay: 1,
					url: URL_V2,
				})
			).toEqual({
				reason: 'UNAVAILABLE',
				verified: false,
			});
			expect(fetchMock).toHaveBeenCalledTimes(3);
		});

		test('should fall back to HTTP_<status> for an error without a JSON body', async () => {
			const fetchMock = vi
				.fn()
				.mockResolvedValue(new Response('Bad Gateway', { status: 502 }));
			expect(
				await verifyServer({
					fetch: fetchMock,
					payload: 'payload',
					url: URL_V2,
				})
			).toEqual({
				reason: 'HTTP_502',
				verified: false,
			});
		});

		test('should retry on network failure and eventually fail', async () => {
			const fetchMock = vi.fn().mockRejectedValue(new Error('fetch failed'));
			const result = await verifyServer({
				fetch: fetchMock,
				payload: 'payload',
				retries: 2,
				retryDelay: 1,
				url: URL_V2,
			});
			expect(result).toEqual({
				reason: 'fetch failed',
				verified: false,
			});
			expect(fetchMock).toHaveBeenCalledTimes(3);
		});

		test('should retry on network failure and eventually succeed', async () => {
			const result = { apiKey: null, verificationData: null, verified: true };
			const fetchMock = vi
				.fn()
				.mockRejectedValueOnce(new Error('fetch failed'))
				.mockResolvedValueOnce(jsonResponse(200, result));
			expect(
				await verifyServer({
					fetch: fetchMock,
					payload: 'payload',
					retries: 1,
					retryDelay: 1,
					url: URL_V2,
				})
			).toEqual(result);
			expect(fetchMock).toHaveBeenCalledTimes(2);
		});

		test('should return aborted result if controller is already aborted', async () => {
			const fetchMock = vi.fn();
			const controller = new AbortController();
			controller.abort();
			expect(
				await verifyServer({
					controller,
					fetch: fetchMock,
					payload: 'payload',
					url: URL_V2,
				})
			).toEqual({
				reason: 'ABORTED',
				verified: false,
			});
			expect(fetchMock).not.toHaveBeenCalled();
		});

		test('should abort and return failed result on timeout', async () => {
			const fetchMock = vi.fn(
				(_url: string, init: RequestInit) =>
					new Promise((_resolve, reject) => {
						init.signal?.addEventListener('abort', () => {
							reject(new Error('AbortError'));
						});
					})
			);
			const result = await verifyServer({
				// @ts-expect-error
				fetch: fetchMock,
				payload: 'payload',
				timeout: 10,
				url: URL_V2,
			});
			expect(result).toEqual({
				reason: 'AbortError',
				verified: false,
			});
		});
	});
});
