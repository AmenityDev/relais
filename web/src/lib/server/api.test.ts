import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { testEnv } = vi.hoisted(() => ({ testEnv: {} as Record<string, string | undefined> }));
vi.mock('$env/dynamic/private', () => ({ env: testEnv }));

const { resetConfigForTests } = await import('./config');
const { ApiCallError, apiFetch } = await import('./api');

function jsonResponse(status: number, body: unknown): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'content-type': 'application/json' }
	});
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
	for (const name of Object.keys(testEnv)) delete testEnv[name];
	Object.assign(testEnv, {
		RELAIS_WEB_API_URL: 'http://relais:8081',
		RELAIS_WEB_ORIGIN: 'https://mail-admin.example.com',
		RELAIS_WEB_OIDC_ISSUER: 'https://auth.example.com/realms/relais',
		RELAIS_WEB_OIDC_CLIENT_ID: 'client',
		RELAIS_WEB_OIDC_CLIENT_SECRET: 'secret',
		RELAIS_WEB_SESSION_KEY: Buffer.alloc(32, 7).toString('base64')
	});
	resetConfigForTests();

	fetchMock = vi.fn();
	vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => vi.unstubAllGlobals());

describe('apiFetch', () => {
	it('attaches the bearer token and asks for JSON', async () => {
		fetchMock.mockResolvedValue(jsonResponse(200, { ok: true }));

		await apiFetch<{ ok: boolean }>('the-token', '/admin/v1/stats');

		const [url, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
		expect(url.toString()).toBe('http://relais:8081/admin/v1/stats');
		const headers = init.headers as Record<string, string>;
		expect(headers.Authorization).toBe('Bearer the-token');
		expect(headers.Accept).toBe('application/json');
		// No body and no content type on a GET: some relays and proxies treat a GET
		// with a content type as malformed.
		expect(init.body).toBeUndefined();
	});

	it('serialises a body and sets the content type exactly once', async () => {
		fetchMock.mockResolvedValue(jsonResponse(201, { id: 'x' }));

		await apiFetch('token', '/admin/v1/backends', { method: 'POST', body: { name: 'relay' } });

		const [, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
		expect(init.method).toBe('POST');
		expect(init.body).toBe('{"name":"relay"}');
		expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json');
	});

	it('drops empty and absent query values instead of sending them', async () => {
		// An empty status would be forwarded as `?status=` and rejected as invalid,
		// turning "no filter" into a 422.
		fetchMock.mockResolvedValue(jsonResponse(200, { data: [] }));

		await apiFetch('token', '/admin/v1/messages', {
			query: { status: '', limit: 25, cursor: undefined }
		});

		const [url] = fetchMock.mock.calls[0] as [URL];
		expect(url.search).toBe('?limit=25');
	});

	it('forwards the request id so the two logs can be joined', async () => {
		fetchMock.mockResolvedValue(jsonResponse(200, {}));

		await apiFetch('token', '/admin/v1/stats', { requestId: 'req-42' });

		const [, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
		expect((init.headers as Record<string, string>)['X-Request-Id']).toBe('req-42');
	});

	it('returns undefined for 204 without reading a body', async () => {
		fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
		await expect(
			apiFetch('token', '/admin/v1/backends/x', { method: 'DELETE' })
		).resolves.toBeUndefined();
	});

	describe('failures', () => {
		it("carries the API's own code and message", async () => {
			// The envelope is the shape the server actually sends. This test previously
			// asserted the bare object, so it passed while the real 422 from relais was
			// reduced to "the admin API returned 422" in the interface.
			fetchMock.mockResolvedValue(
				jsonResponse(422, {
					error: {
						code: 'invalid_request',
						message: 'port must be 1-65535',
						field: 'port'
					}
				})
			);

			const error = await apiFetch('token', '/admin/v1/backends', {
				method: 'POST',
				body: {}
			}).catch((cause: unknown) => cause);

			expect(error).toBeInstanceOf(ApiCallError);
			const api = error as InstanceType<typeof ApiCallError>;
			expect(api.status).toBe(422);
			expect(api.code).toBe('invalid_request');
			expect(api.message).toBe('port must be 1-65535');
			expect(api.field).toBe('port');
		});

		it('does not expose a non-JSON error body', async () => {
			// A proxy in front of the API can answer with an HTML page. Surfacing it
			// would put whatever it contains on an operator's screen.
			fetchMock.mockResolvedValue(
				new Response('<html><body>Gateway Timeout — upstream relais-internal:8081</body></html>', {
					status: 504
				})
			);

			const error = (await apiFetch('token', '/admin/v1/stats').catch(
				(cause: unknown) => cause
			)) as InstanceType<typeof ApiCallError>;

			expect(error.status).toBe(504);
			expect(error.message).toBe('the admin API returned 504');
			expect(error.message).not.toContain('relais-internal');
		});

		it('reports an unreachable API as 503, not as a session problem', async () => {
			// If this surfaced as 401 the operator would be signed out and would try
			// again, and again, while the real problem is that the API is down.
			fetchMock.mockRejectedValue(new Error('ECONNREFUSED 10.0.0.4:8081'));

			const error = (await apiFetch('token', '/admin/v1/stats').catch(
				(cause: unknown) => cause
			)) as InstanceType<typeof ApiCallError>;

			expect(error.status).toBe(503);
			expect(error.code).toBe('api_unreachable');
			// The underlying error names an internal address; it must not be repeated.
			expect(error.message).not.toContain('10.0.0.4');
		});

		it('falls back cleanly when the envelope is missing', async () => {
			// A proxy or a future version could answer with something else. The status is
			// still reported; only the message degrades.
			fetchMock.mockResolvedValue(jsonResponse(500, { unexpected: true }));

			const error = (await apiFetch('token', '/admin/v1/stats').catch(
				(cause: unknown) => cause
			)) as InstanceType<typeof ApiCallError>;

			expect(error.status).toBe(500);
			expect(error.code).toBe('unknown');
		});

		it('reports a success body that is not JSON as 502', async () => {
			fetchMock.mockResolvedValue(new Response('not json', { status: 200 }));

			const error = (await apiFetch('token', '/admin/v1/stats').catch(
				(cause: unknown) => cause
			)) as InstanceType<typeof ApiCallError>;

			expect(error.status).toBe(502);
			expect(error.code).toBe('invalid_response');
		});
	});
});
