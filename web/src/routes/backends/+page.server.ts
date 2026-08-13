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
		return {
			backends: list.data,
			// The API returns every row today and sets no cursor. If it ever starts
			// paginating this endpoint, showing page one silently would hide rows from
			// an operator making a decision; surfacing the cursor's presence does not.
			truncated: list.next_cursor !== undefined,
			canWrite: identity?.can_write === true
		};
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

	update: async ({ locals, request }) => {
		const form = await request.formData();
		const id = String(form.get('id') ?? '');
		const password = String(form.get('password') ?? '');

		// Every field is sent, because the API's PATCH starts from the stored row and
		// this form showed the operator all of them. The one exception is the password:
		// it is never displayed, so an empty box means "leave it alone" rather than
		// "clear it" — sending an empty string would wipe the relay's credential every
		// time someone renamed it.
		const body = {
			name: String(form.get('name') ?? '').trim(),
			host: String(form.get('host') ?? '').trim(),
			port: Number(form.get('port') ?? 587),
			tls_mode: String(form.get('tls_mode') ?? 'starttls'),
			auth_user: String(form.get('auth_user') ?? '').trim(),
			helo_name: String(form.get('helo_name') ?? '').trim(),
			max_concurrency: Number(form.get('max_concurrency') ?? 2),
			enabled: form.get('enabled') === 'on',
			...(password === '' ? {} : { password })
		};

		try {
			await apiFetch<Backend>(
				requireSession(locals).accessToken,
				`/admin/v1/backends/${encodeURIComponent(id)}`,
				{ method: 'PATCH', body, requestId: locals.requestId }
			);
			return { updated: true };
		} catch (cause) {
			const { password: _password, ...safe } = body as Record<string, unknown>;
			return formFail(cause, safe);
		}
	},

	// Enabling and disabling is its own action rather than a trip through the edit
	// form. A domain pointing at a disabled relay delivers nothing, so this is the
	// switch an operator reaches for during an incident, and it should be one click.
	toggle: async ({ locals, request }) => {
		const form = await request.formData();
		const id = String(form.get('id') ?? '');
		const enabled = form.get('enabled') === 'true';

		try {
			await apiFetch<Backend>(
				requireSession(locals).accessToken,
				`/admin/v1/backends/${encodeURIComponent(id)}`,
				{ method: 'PATCH', body: { enabled }, requestId: locals.requestId }
			);
			return { updated: true };
		} catch (cause) {
			return formFail(cause, {});
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
