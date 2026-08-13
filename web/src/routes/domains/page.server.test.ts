import { beforeEach, describe, expect, it, vi } from 'vitest';

const { apiFetchMock } = vi.hoisted(() => ({ apiFetchMock: vi.fn() }));

vi.mock('$lib/server/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/server/api')>('$lib/server/api');
	return { ...actual, apiFetch: apiFetchMock };
});
vi.mock('$lib/server/session', () => ({
	requireSession: () => ({ accessToken: 'test-token' })
}));

const { actions, load } = await import('./+page.server');

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
	apiFetchMock.mockResolvedValue({ data: [] });
});

describe('the domains load', () => {
	it('runs the resolve dry run only when a sender was given', async () => {
		await load({
			locals: { requestId: 'req-1' },
			parent: async () => ({ identity: { can_write: true } }),
			url: new URL('http://localhost:3000/domains')
		} as never);

		const paths = apiFetchMock.mock.calls.map((c) => c[1]);
		expect(paths).not.toContain('/admin/v1/domains:resolve');
	});

	it('runs it on load when a sender is in the query, not behind a click', async () => {
		// A failing configuration poses exactly this question, so answering it costs one
		// round trip and saves a step.
		await load({
			locals: { requestId: 'req-1' },
			parent: async () => ({ identity: { can_write: true } }),
			url: new URL('http://localhost:3000/domains?sender=a@x.test')
		} as never);

		const paths = apiFetchMock.mock.calls.map((c) => c[1]);
		expect(paths).toContain('/admin/v1/domains:resolve');
	});
});

describe('the domain update action', () => {
	it('maps both checkboxes', async () => {
		await actions.update!(
			event({ id: 'd1', name: 'x.test', backend_id: 'b1', include_subdomains: 'on' })
		);
		expect(sentBody().include_subdomains).toBe(true);
		expect(sentBody().enabled).toBe(false);

		await actions.update!(event({ id: 'd1', name: 'x.test', backend_id: 'b1', enabled: 'on' }));
		expect(sentBody().include_subdomains).toBe(false);
		expect(sentBody().enabled).toBe(true);
	});

	it('sends the backend id, so a domain can be repointed', async () => {
		await actions.update!(event({ id: 'd1', name: 'x.test', backend_id: 'b-new' }));
		expect(sentBody().backend_id).toBe('b-new');
	});
});
