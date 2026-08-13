import { fail } from '@sveltejs/kit';
import {
	ApiCallError,
	apiFetch,
	failWith,
	type CreatedCredential,
	type Credential
} from '$lib/server/api';
import { requireSession } from '$lib/server/session';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals, parent }) => {
	const { identity } = await parent();
	try {
		const list = await apiFetch<{ data: Credential[]; next_cursor?: string }>(
			requireSession(locals).accessToken,
			'/admin/v1/credentials',
			{ requestId: locals.requestId }
		);
		return {
			credentials: list.data,
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

export const actions: Actions = {
	create: async ({ locals, request }) => {
		const form = await request.formData();
		const patterns = String(form.get('patterns') ?? '')
			.split(/[\s,]+/)
			.filter((p) => p !== '');

		const body = {
			name: String(form.get('name') ?? '').trim(),
			type: String(form.get('type') ?? 'api_key'),
			username: String(form.get('username') ?? '').trim(),
			patterns
		};

		try {
			const created = await apiFetch<CreatedCredential>(
				requireSession(locals).accessToken,
				'/admin/v1/credentials',
				{ method: 'POST', body, requestId: locals.requestId }
			);
			// Returned to the page rather than redirected to: a redirect would discard
			// the secret, and it exists in this one response only.
			return { created };
		} catch (cause) {
			if (cause instanceof ApiCallError && [403, 409, 422].includes(cause.status)) {
				return fail(cause.status, {
					message: cause.message,
					field: cause.field,
					values: { ...body, patterns: patterns.join('\n') }
				});
			}
			failWith(cause);
		}
	},

	update: async ({ locals, request }) => {
		const form = await request.formData();
		const id = String(form.get('id') ?? '');
		const rps = String(form.get('rate_limit_rps') ?? '').trim();
		const burst = String(form.get('rate_limit_burst') ?? '').trim();

		// An empty rate limit means "use the deployment default", which the API spells
		// as null. Sending 0 would mean a credential that can never send.
		const body = {
			name: String(form.get('name') ?? '').trim(),
			enabled: form.get('enabled') === 'on',
			rate_limit_rps: rps === '' ? null : Number(rps),
			rate_limit_burst: burst === '' ? null : Number(burst)
		};

		try {
			await apiFetch<Credential>(
				requireSession(locals).accessToken,
				`/admin/v1/credentials/${encodeURIComponent(id)}`,
				{ method: 'PATCH', body, requestId: locals.requestId }
			);
			return { updated: true };
		} catch (cause) {
			if (cause instanceof ApiCallError && [403, 409, 422].includes(cause.status)) {
				return fail(cause.status, { message: cause.message, field: cause.field, values: body });
			}
			failWith(cause);
		}
	},

	revoke: async ({ locals, request }) => {
		const form = await request.formData();
		const id = String(form.get('id') ?? '');
		try {
			await apiFetch<Credential>(
				requireSession(locals).accessToken,
				`/admin/v1/credentials/${encodeURIComponent(id)}:revoke`,
				{ method: 'POST', requestId: locals.requestId }
			);
			return { revoked: true };
		} catch (cause) {
			if (cause instanceof ApiCallError && [403, 404].includes(cause.status)) {
				return fail(cause.status, { message: cause.message, values: {} });
			}
			failWith(cause);
		}
	}
};
