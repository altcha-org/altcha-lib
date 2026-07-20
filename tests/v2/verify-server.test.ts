import { describe, expect, test, vi } from 'vitest';
import { verifyServer } from '../../src/v2/verify-server.js';

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
					url: 'https://sentinel.example.com/v1/verify/signature',
				})
			).toEqual(result);
			expect(fetchMock).toHaveBeenCalledTimes(1);
		});

		test('should send secret in the request body when provided', async () => {
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
				url: 'https://sentinel.example.com/v1/verify/signature',
			});
			const [, init] = fetchMock.mock.calls[0];
			expect(JSON.parse(init.body)).toEqual({
				payload: 'payload',
				secret: 'sec_123',
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
					url: 'https://sentinel.example.com/v1/verify/signature',
				})
			).toEqual(result);
		});

		test('should not retry on 400 bad request', async () => {
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
					url: 'https://sentinel.example.com/v1/verify/signature',
				})
			).toEqual({
				reason: 'INVALID_PAYLOAD',
				verified: false,
			});
			expect(fetchMock).toHaveBeenCalledTimes(1);
		});

		test('should retry on network failure and eventually fail', async () => {
			const fetchMock = vi.fn().mockRejectedValue(new Error('fetch failed'));
			const result = await verifyServer({
				fetch: fetchMock,
				payload: 'payload',
				retries: 2,
				retryDelay: 1,
				url: 'https://sentinel.example.com/v1/verify/signature',
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
					url: 'https://sentinel.example.com/v1/verify/signature',
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
					url: 'https://sentinel.example.com/v1/verify/signature',
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
				url: 'https://sentinel.example.com/v1/verify/signature',
			});
			expect(result).toEqual({
				reason: 'AbortError',
				verified: false,
			});
		});
	});
});
