import { beforeEach, describe, expect, it, vi } from 'vitest';

const { apiFetchMock } = vi.hoisted(() => ({ apiFetchMock: vi.fn() }));

vi.mock('$lib/server/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/server/api')>('$lib/server/api');
	return { ...actual, apiFetch: apiFetchMock };
});
vi.mock('$lib/server/session', () => ({
	requireSession: () => ({ accessToken: 'test-token' })
}));

const { ApiCallError } = await import('$lib/server/api');
const { actions } = await import('./+page.server');

type Actions = typeof actions;

function event(fields: Record<string, string>) {
	const body = new URLSearchParams(fields);
	return {
		locals: { requestId: 'req-1' },
		request: { formData: async () => body }
	} as unknown as Parameters<NonNullable<Actions['update']>>[0];
}

function sentBody(): Record<string, unknown> {
	const call = apiFetchMock.mock.calls.at(-1);
	return (call?.[2] as { body?: Record<string, unknown> })?.body ?? {};
}

beforeEach(() => {
	apiFetchMock.mockReset();
	apiFetchMock.mockResolvedValue({});
});

describe('creating a credential', () => {
	it('splits the pattern box on whitespace and commas', async () => {
		await actions.create!(
			event({ name: 'app', type: 'api_key', patterns: 'a@x.test, b@x.test\nc@x.test' })
		);
		expect(sentBody().patterns).toEqual(['a@x.test', 'b@x.test', 'c@x.test']);
	});

	it('sends an empty list rather than a list containing an empty string', async () => {
		// A pattern of "" would be rejected by the grammar, and the rejection would name
		// a pattern the operator never typed.
		await actions.create!(event({ name: 'app', type: 'api_key', patterns: '  \n , ' }));
		expect(sentBody().patterns).toEqual([]);
	});

	it('returns the created credential so the secret can be shown once', async () => {
		// Not a redirect: a redirect would discard the response, and the secret exists in
		// that one response only. relais stores a peppered HMAC and cannot show it again.
		apiFetchMock.mockResolvedValue({ credential: { id: 'c1' }, secret: 'relais_sk_xyz' });

		const result = (await actions.create!(
			event({ name: 'app', type: 'api_key', patterns: 'a@x.test' })
		)) as { created: { secret: string } };

		expect(result.created.secret).toBe('relais_sk_xyz');
	});

	it('keeps the typed patterns on a failure, as text rather than as an array', async () => {
		apiFetchMock.mockRejectedValue(new ApiCallError(422, 'invalid_pattern', 'bad pattern'));

		const result = (await actions.create!(
			event({ name: 'app', type: 'api_key', patterns: 'a@x.test\nbad' })
		)) as { data: { values: { patterns: string } } };

		expect(result.data.values.patterns).toBe('a@x.test\nbad');
	});
});

describe('updating a credential', () => {
	it('sends null for an empty rate limit, not zero', async () => {
		// null means "use the deployment default". Zero would mean a credential that can
		// never send, which is not what an empty box asks for.
		await actions.update!(
			event({ id: 'c1', name: 'app', rate_limit_rps: '', rate_limit_burst: '' })
		);

		expect(sentBody().rate_limit_rps).toBeNull();
		expect(sentBody().rate_limit_burst).toBeNull();
	});

	it('sends the numbers when they are given', async () => {
		await actions.update!(
			event({ id: 'c1', name: 'app', rate_limit_rps: '2.5', rate_limit_burst: '10' })
		);
		expect(sentBody().rate_limit_rps).toBe(2.5);
		expect(sentBody().rate_limit_burst).toBe(10);
	});

	it('maps the enabled checkbox', async () => {
		await actions.update!(event({ id: 'c1', name: 'app', enabled: 'on' }));
		expect(sentBody().enabled).toBe(true);

		await actions.update!(event({ id: 'c1', name: 'app' }));
		expect(sentBody().enabled).toBe(false);
	});
});

describe('revoking a credential', () => {
	it('posts to the revoke sub-resource rather than deleting', async () => {
		// Revocation is deliberately not a delete: the messages this credential sent keep
		// pointing at it, which is what makes an audit possible.
		await actions.revoke!(event({ id: 'c-9' }));

		const call = apiFetchMock.mock.calls.at(-1);
		expect(call?.[1]).toBe('/admin/v1/credentials/c-9:revoke');
		expect((call?.[2] as { method: string }).method).toBe('POST');
	});
});
