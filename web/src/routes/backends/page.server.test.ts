import { beforeEach, describe, expect, it, vi } from 'vitest';

// Route tests: the load functions and form actions, with the API mocked.
//
// These cover the layer between a form and the API — where a checkbox becomes a
// boolean, an empty field becomes an absent key rather than an empty one, and an API
// refusal becomes something a screen can render. Every bug found in this layer so far
// has been of that kind, and none of them would show up in a type check.

const { apiFetchMock } = vi.hoisted(() => ({ apiFetchMock: vi.fn() }));

// ApiCallError is a real class here: the actions branch on `instanceof`, so a stub
// object would make every one of those branches untestable.
vi.mock('$lib/server/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/server/api')>('$lib/server/api');
	return { ...actual, apiFetch: apiFetchMock };
});

vi.mock('$lib/server/session', () => ({
	requireSession: () => ({ accessToken: 'test-token' })
}));

const { ApiCallError } = await import('$lib/server/api');
const { actions, load } = await import('./+page.server');
const { loaded } = await import('../load-result');

type Actions = typeof actions;

function event(fields: Record<string, string>) {
	const body = new URLSearchParams(fields);
	return {
		locals: { requestId: 'req-1' },
		request: { formData: async () => body }
	} as unknown as Parameters<NonNullable<Actions['update']>>[0];
}

/** The last body passed to apiFetch. */
function sentBody(): Record<string, unknown> {
	const call = apiFetchMock.mock.calls.at(-1);
	return (call?.[2] as { body?: Record<string, unknown> })?.body ?? {};
}

beforeEach(() => {
	apiFetchMock.mockReset();
	apiFetchMock.mockResolvedValue({ data: [] });
});

describe('load', () => {
	it('reports canWrite from the identity, never from the token', async () => {
		// Go is the authority on the role (F6). The screen reflects what the API said.
		apiFetchMock.mockResolvedValue({ data: [{ id: 'b1' }] });

		const result = loaded(
			await load({
				locals: { requestId: 'req-1' },
				parent: async () => ({ identity: { can_write: false } })
			} as never)
		);

		expect(result.canWrite).toBe(false);
		expect(result.backends).toHaveLength(1);
	});

	it('flags a truncated list rather than showing page one silently', async () => {
		apiFetchMock.mockResolvedValue({ data: [{ id: 'b1' }], next_cursor: 'abc' });

		const result = loaded(
			await load({
				locals: { requestId: 'req-1' },
				parent: async () => ({ identity: { can_write: true } })
			} as never)
		);

		expect(result.truncated).toBe(true);
	});

	it('does not flag a complete list', async () => {
		const result = loaded(
			await load({
				locals: { requestId: 'req-1' },
				parent: async () => ({ identity: { can_write: true } })
			} as never)
		);

		expect(result.truncated).toBe(false);
	});
});

describe('the update action', () => {
	it('omits the password when the field was left empty', async () => {
		// The API treats an absent password as "keep the stored one" and an empty string
		// as a value. Sending "" would wipe a relay's credential every time someone
		// renamed it, and relais cannot show the password again to put it back.
		await actions.update!(
			event({
				id: 'b1',
				name: 'relay',
				host: 'smtp.example.test',
				port: '587',
				tls_mode: 'starttls',
				auth_user: 'user',
				helo_name: '',
				max_concurrency: '2',
				enabled: 'on',
				password: ''
			})
		);

		expect('password' in sentBody()).toBe(false);
	});

	it('sends the password when one was typed', async () => {
		await actions.update!(
			event({ id: 'b1', name: 'relay', host: 'h', port: '25', password: 'new-secret' })
		);
		expect(sentBody().password).toBe('new-secret');
	});

	it('translates a checkbox into a boolean', async () => {
		await actions.update!(event({ id: 'b1', name: 'relay', host: 'h', port: '25' }));
		expect(sentBody().enabled).toBe(false);

		await actions.update!(event({ id: 'b1', name: 'relay', host: 'h', port: '25', enabled: 'on' }));
		expect(sentBody().enabled).toBe(true);
	});

	it('sends the port as a number', async () => {
		await actions.update!(event({ id: 'b1', name: 'relay', host: 'h', port: '2525' }));
		expect(sentBody().port).toBe(2525);
	});

	it('uses PATCH on the right path', async () => {
		await actions.update!(event({ id: 'b-1', name: 'relay', host: 'h', port: '25' }));
		const call = apiFetchMock.mock.calls.at(-1);
		expect(call?.[1]).toBe('/admin/v1/backends/b-1');
		expect((call?.[2] as { method: string }).method).toBe('PATCH');
	});

	it("returns the API's own message on a 422, and keeps the typed values", async () => {
		// The message is the useful part: "backend auth password was given without a
		// user" tells an operator what to change, a bare 422 does not.
		apiFetchMock.mockRejectedValue(
			new ApiCallError(422, 'invalid_request', 'port must be 1-65535', 'port')
		);

		const result = (await actions.update!(
			event({ id: 'b1', name: 'relay', host: 'h', port: '70000' })
		)) as {
			status: number;
			data: { message: string; field?: string; values: Record<string, unknown> };
		};

		expect(result.status).toBe(422);
		expect(result.data.message).toBe('port must be 1-65535');
		expect(result.data.field).toBe('port');
		expect(result.data.values.name).toBe('relay');
	});

	it('never echoes the password back into the form', async () => {
		// A failed save re-renders the form from these values. Putting the password
		// there would print it in the HTML.
		apiFetchMock.mockRejectedValue(new ApiCallError(422, 'invalid_request', 'nope'));

		const result = (await actions.update!(
			event({ id: 'b1', name: 'relay', host: 'h', port: '25', password: 'super-secret' })
		)) as { data: { values: Record<string, unknown> } };

		expect(JSON.stringify(result.data.values)).not.toContain('super-secret');
		expect('password' in result.data.values).toBe(false);
	});

	it('turns a 403 into a read-only message rather than an error page', async () => {
		// A viewer clicking a control that should not have been rendered deserves an
		// explanation, not a stack of status codes. The API is what enforces this.
		apiFetchMock.mockRejectedValue(new ApiCallError(403, 'forbidden', 'forbidden'));

		const result = (await actions.update!(
			event({ id: 'b1', name: 'x', host: 'h', port: '25' })
		)) as {
			status: number;
			data: { message: string };
		};

		expect(result.status).toBe(403);
		expect(result.data.message).toMatch(/read-only/i);
	});
});

describe('the toggle action', () => {
	it('sends only the enabled flag, so nothing else can be changed by accident', async () => {
		await actions.toggle!(event({ id: 'b1', enabled: 'true' }));
		expect(sentBody()).toEqual({ enabled: true });
	});

	it('reads the target state from the form rather than inverting a guess', async () => {
		await actions.toggle!(event({ id: 'b1', enabled: 'false' }));
		expect(sentBody()).toEqual({ enabled: false });
	});
});

describe('the remove action', () => {
	it('explains a 409 in terms of what to do about it', async () => {
		// The refusal an operator actually meets: a relay in use cannot be deleted.
		apiFetchMock.mockRejectedValue(new ApiCallError(409, 'referenced', 'still referenced'));

		const result = (await actions.remove!(event({ id: 'b1' }))) as {
			status: number;
			data: { message: string };
		};

		expect(result.status).toBe(409);
		expect(result.data.message).toMatch(/domain still points at this relay/i);
	});
});

describe('the probe action', () => {
	it('returns the result under the id it was run for', async () => {
		// Several relays can be listed; the screen has to know which row the answer
		// belongs to.
		apiFetchMock.mockResolvedValue({ ok: true, used_tls: true, authenticated: true });

		const result = (await actions.probe!(event({ id: 'b-42' }))) as {
			probe: { id: string; result: { ok: boolean } };
		};

		expect(result.probe.id).toBe('b-42');
		expect(result.probe.result.ok).toBe(true);
	});
});
