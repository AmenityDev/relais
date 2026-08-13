import { fail } from '@sveltejs/kit';
import { ApiCallError, apiFetch, failWith, type Backend, type ProbeResult } from '$lib/server/api';
import { requireSession } from '$lib/server/session';
import type { Actions, PageServerLoad } from './$types';

interface BackendList {
	data: Backend[];
	next_cursor?: string;
}

export const load: PageServerLoad = async ({ locals, parent }) => {
	const { identity } = await parent();
	try {
		const list = await apiFetch<BackendList>(
			requireSession(locals).accessToken,
			'/admin/v1/backends',
			{ requestId: locals.requestId }
		);
		return { backends: list.data, canWrite: identity?.can_write === true };
	} catch (cause) {
		failWith(cause);
	}
};

// Actions do not pre-check the role, and that is deliberate.
//
// A form action has no access to parent(), so checking here would mean either an
// extra round trip for the identity or mapping groups to a role in TypeScript. The
// second would be a second implementation of the decision Go already owns (F6),
// free to disagree with it. So the API decides, and its 403 is translated below.
// The interface still hides write controls from a viewer, using the identity the
// layout already loaded — that is presentation, not enforcement.

/**
 * Turns an API rejection into something a form can render.
 *
 * `fail` rather than `error`: a 422 is the operator's input being wrong, and
 * replacing the page with an error screen would throw away everything they typed.
 * A 403 gets a message that says why rather than a bare status.
 */
function formFail(cause: unknown, values: Record<string, unknown>) {
	if (cause instanceof ApiCallError) {
		if (cause.status === 422 || cause.status === 409) {
			return fail(cause.status, { message: cause.message, field: cause.field, values });
		}
		if (cause.status === 403) {
			return fail(403, {
				message: 'Your account has read-only access to relais.',
				values
			});
		}
	}
	failWith(cause);
}

export const actions: Actions = {
	create: async ({ locals, request }) => {
		const form = await request.formData();
		const password = String(form.get('password') ?? '');

		const body = {
			name: String(form.get('name') ?? '').trim(),
			host: String(form.get('host') ?? '').trim(),
			port: Number(form.get('port') ?? 587),
			tls_mode: String(form.get('tls_mode') ?? 'starttls'),
			auth_user: String(form.get('auth_user') ?? '').trim(),
			helo_name: String(form.get('helo_name') ?? '').trim(),
			// Absent rather than empty: the API treats an empty string as "set it to
			// nothing", and a create with no password is a relay that takes none.
			...(password === '' ? {} : { password })
		};

		try {
			await apiFetch<Backend>(requireSession(locals).accessToken, '/admin/v1/backends', {
				method: 'POST',
				body,
				requestId: locals.requestId
			});
			return { created: true };
		} catch (cause) {
			// The password is deliberately not echoed back into the form values.
			const { password: _password, ...safe } = body as Record<string, unknown>;
			return formFail(cause, safe);
		}
	},

	probe: async ({ locals, request }) => {
		const form = await request.formData();
		const id = String(form.get('id') ?? '');

		try {
			const result = await apiFetch<ProbeResult>(
				requireSession(locals).accessToken,
				`/admin/v1/backends/${encodeURIComponent(id)}:test`,
				{ method: 'POST', requestId: locals.requestId }
			);
			return { probe: { id, result } };
		} catch (cause) {
			return formFail(cause, {});
		}
	},

	remove: async ({ locals, request }) => {
		const form = await request.formData();
		const id = String(form.get('id') ?? '');

		try {
			await apiFetch<void>(
				requireSession(locals).accessToken,
				`/admin/v1/backends/${encodeURIComponent(id)}`,
				{ method: 'DELETE', requestId: locals.requestId }
			);
			return { removed: true };
		} catch (cause) {
			if (cause instanceof ApiCallError && cause.status === 409) {
				// The most common refusal, and the message that saves a support round
				// trip: a relay in use cannot be deleted.
				return fail(409, {
					message: 'A sending domain still points at this relay. Repoint or remove it first.',
					values: {}
				});
			}
			return formFail(cause, {});
		}
	}
};
