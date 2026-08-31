import { beforeEach, describe, expect, it, vi } from 'vitest';

const { apiFetchMock } = vi.hoisted(() => ({ apiFetchMock: vi.fn() }));

vi.mock('$lib/server/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/server/api')>('$lib/server/api');
	return { ...actual, apiFetch: apiFetchMock };
});
vi.mock('$lib/server/session', () => ({
	requireSession: () => ({ accessToken: 'test-token' })
}));
vi.mock('$lib/server/logs', () => ({ credentialLogsUrl: () => '' }));

const { actions, load } = await import('./+page.server');

type Actions = typeof actions;

function event(fields: Record<string, string>) {
	const body = new URLSearchParams(fields);
	return {
		locals: { requestId: 'req-1' },
		params: { id: 'cred-1' },
		request: { formData: async () => body }
	} as unknown as Parameters<NonNullable<Actions['addRecipient']>>[0];
}

function lastCall(): { path: string; method?: string; body?: Record<string, unknown> } {
	const call = apiFetchMock.mock.calls.at(-1);
	return {
		path: call?.[1] as string,
		...((call?.[2] ?? {}) as { method?: string; body?: Record<string, unknown> })
	};
}

beforeEach(() => {
	apiFetchMock.mockReset();
	apiFetchMock.mockResolvedValue({ data: [] });
});

describe('loading the credential', () => {
	it('fetches both allow-lists, and keeps them apart', async () => {
		// The two lists come from different endpoints and mean opposite things when
		// empty, so the load must not conflate them.
		apiFetchMock.mockImplementation(async (_token: string, path: string) => {
			if (path.endsWith('/recipient-patterns'))
				return { data: [{ id: 'r1', pattern: '*@team.test' }] };
			if (path.endsWith('/patterns')) return { data: [{ id: 'p1', pattern: 'a@x.test' }] };
			return { id: 'cred-1', name: 'app' };
		});

		const data = (await load!({
			locals: { requestId: 'req-1' },
			params: { id: 'cred-1' },
			parent: async () => ({ identity: { can_write: true } })
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		} as any)) as { patterns: { pattern: string }[]; recipientPatterns: { pattern: string }[] };

		expect(data.patterns.map((p) => p.pattern)).toEqual(['a@x.test']);
		expect(data.recipientPatterns.map((p) => p.pattern)).toEqual(['*@team.test']);
	});
});

describe('the recipient allow-list', () => {
	it('posts to the recipient endpoint, not the sender one', async () => {
		// The bug this guards against would silently widen what a credential may send
		// as while the operator believed they were narrowing who it can reach.
		await actions.addRecipient!(event({ patterns: '*@team.test' }));

		const call = lastCall();
		expect(call.path).toBe('/admin/v1/credentials/cred-1/recipient-patterns');
		expect(call.method).toBe('POST');
		expect(call.body?.patterns).toEqual(['*@team.test']);
	});

	it('splits the box on whitespace and commas', async () => {
		await actions.addRecipient!(event({ patterns: 'a@x.test, b@x.test\nc@x.test' }));
		expect(lastCall().body?.patterns).toEqual(['a@x.test', 'b@x.test', 'c@x.test']);
	});

	it('keeps what was typed when the API refuses it', async () => {
		const { ApiCallError } = await import('$lib/server/api');
		apiFetchMock.mockRejectedValue(new ApiCallError(422, 'invalid_request', 'bad pattern'));

		const result = (await actions.addRecipient!(event({ patterns: 'a@x.test\n*@*' }))) as {
			status: number;
			data: { values: Record<string, string> };
		};

		expect(result.status).toBe(422);
		// Re-rendered into the textarea: retyping a list because one entry was wrong is
		// how an operator ends up pasting a shorter list than they meant.
		expect(result.data.values.recipient_patterns).toBe('a@x.test\n*@*');
	});

	it('deletes through the recipient path', async () => {
		await actions.removeRecipient!(event({ pattern_id: 'r1' }));
		const call = lastCall();
		expect(call.path).toBe('/admin/v1/credentials/cred-1/recipient-patterns/r1');
		expect(call.method).toBe('DELETE');
	});

	it('returns the dry run, restriction flag and all', async () => {
		// restricted=false with allowed=true is "allowed because nothing is
		// configured", and the page renders that differently from a rule matching.
		apiFetchMock.mockResolvedValue({
			address: 'x@y.test',
			allowed: true,
			restricted: false,
			patterns: []
		});

		const result = (await actions.testRecipient!(event({ address: 'x@y.test' }))) as {
			recipientTest: { allowed: boolean; restricted: boolean };
		};

		expect(lastCall().path).toBe('/admin/v1/credentials/cred-1/recipient-patterns:test');
		expect(result.recipientTest).toEqual({
			address: 'x@y.test',
			allowed: true,
			restricted: false,
			patterns: []
		});
	});
});

describe('the sender allow-list still goes where it did', () => {
	it('posts to the sender endpoint', async () => {
		await actions.add!(event({ patterns: 'a@x.test' }));
		expect(lastCall().path).toBe('/admin/v1/credentials/cred-1/patterns');
	});

	it('deletes through the sender path', async () => {
		await actions.remove!(event({ pattern_id: 'p1' }));
		expect(lastCall().path).toBe('/admin/v1/credentials/cred-1/patterns/p1');
	});
});
