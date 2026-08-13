import { beforeEach, describe, expect, it, vi } from 'vitest';

const { apiFetchMock } = vi.hoisted(() => ({ apiFetchMock: vi.fn() }));

vi.mock('$lib/server/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/server/api')>('$lib/server/api');
	return { ...actual, apiFetch: apiFetchMock };
});
vi.mock('$lib/server/session', () => ({
	requireSession: () => ({ accessToken: 'test-token' })
}));

const { load } = await import('./+page.server');
const { loaded } = await import('../load-result');

function query(search: string) {
	return {
		locals: { requestId: 'req-1' },
		url: new URL(`http://localhost:3000/messages${search}`)
	} as never;
}

function sentQuery(): Record<string, unknown> {
	const call = apiFetchMock.mock.calls.at(-1);
	return (call?.[2] as { query?: Record<string, unknown> })?.query ?? {};
}

beforeEach(() => {
	apiFetchMock.mockReset();
	apiFetchMock.mockResolvedValue({ data: [] });
});

describe('the message list', () => {
	it('forwards a known status', async () => {
		await load(query('?status=failed'));
		expect(sentQuery().status).toBe('failed');
	});

	it('drops an unknown status instead of forwarding it', async () => {
		// A status from a hand-edited URL would come back as a 422 rendered as an error
		// page. The honest answer to a bad filter is to ignore the filter, not to replace
		// the screen with a stack trace.
		await load(query('?status=whatever'));
		expect('status' in sentQuery()).toBe(false);
	});

	it('does not forward an injection attempt as a filter', async () => {
		await load(query('?status=' + encodeURIComponent("sent' OR 1=1")));
		expect('status' in sentQuery()).toBe(false);
	});

	it('forwards a cursor when there is one', async () => {
		await load(query('?cursor=abc123'));
		expect(sentQuery().cursor).toBe('abc123');
	});

	it('omits an empty cursor rather than sending a blank one', async () => {
		await load(query('?cursor='));
		expect('cursor' in sentQuery()).toBe(false);
	});

	it('passes the next cursor through for the pager', async () => {
		apiFetchMock.mockResolvedValue({ data: [{ id: 'm1' }], next_cursor: 'next' });
		const result = loaded(await load(query('')));
		expect(result.nextCursor).toBe('next');
	});

	it('offers exactly the statuses the API documents', async () => {
		// Rendering a filter the API rejects would be a dead control.
		const result = loaded(await load(query('')));
		expect([...result.statuses]).toEqual([
			'queued',
			'sending',
			'sent',
			'failed',
			'rejected',
			'partial'
		]);
	});
});
