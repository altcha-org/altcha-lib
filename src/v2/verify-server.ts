import { delay } from './helpers.js';
import type { VerifyServerOptions, VerifyServerResult } from './types.js';

/** Verifies a payload remotely via the ALTCHA Sentinel `/v1/verify/signature` API. */
export async function verifyServer(
	options: VerifyServerOptions
): Promise<VerifyServerResult> {
	const {
		controller,
		fetch: fetchImpl = fetch,
		headers,
		payload,
		retries = 0,
		retryBackoff = 'exponential',
		retryDelay = 300,
		secret,
		timeout = 10_000,
		url,
	} = options;
	const body = JSON.stringify({ payload, secret });

	for (let attempt = 0; attempt <= retries; attempt++) {
		if (controller?.signal.aborted) {
			return { verified: false, reason: 'ABORTED' };
		}
		const attemptController = new AbortController();
		const onAbort = () => attemptController.abort();
		controller?.signal.addEventListener('abort', onAbort);
		const timer = setTimeout(() => attemptController.abort(), timeout);
		try {
			const response = await fetchImpl(url, {
				body,
				headers: {
					'Content-Type': 'application/json',
					...headers,
				},
				method: 'POST',
				signal: attemptController.signal,
			});
			if (response.status === 400) {
				const data = await response
					.json()
					.catch(() => null as { error?: string } | null);
				return {
					verified: false,
					reason: data?.error ?? `HTTP_${response.status}`,
				};
			}
			if (!response.ok) {
				throw new Error(`HTTP_${response.status}`);
			}
			return (await response.json()) as VerifyServerResult;
		} catch (err) {
			if (attempt >= retries) {
				return {
					verified: false,
					reason: err instanceof Error ? err.message : 'NETWORK_ERROR',
				};
			}
			const backoffDelay =
				retryBackoff === 'fixed' ? retryDelay : retryDelay * 2 ** attempt;
			await delay(backoffDelay);
		} finally {
			clearTimeout(timer);
			controller?.signal.removeEventListener('abort', onAbort);
		}
	}
	return { verified: false, reason: 'NETWORK_ERROR' };
}
