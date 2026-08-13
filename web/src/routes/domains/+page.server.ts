import { fail } from '@sveltejs/kit';
import {
	ApiCallError,
	apiFetch,
	failWith,
	type Backend,
	type Domain,
	type ResolveResult
} from '$lib/server/api';
import { requireSession } from '$lib/server/session';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals, parent, url }) => {
	const { identity } = await parent();
	const token = requireSession(locals).accessToken;
	const requestId = locals.requestId;
	const sender = url.searchParams.get('sender') ?? '';

	try {
		const [domains, backends] = await Promise.all([
			apiFetch<{ data: Domain[] }>(token, '/admin/v1/domains', { requestId }),
			apiFetch<{ data: Backend[] }>(token, '/admin/v1/backends', { requestId })
		]);

		// The dry run answers the question a broken configuration actually poses, so
		// it runs on load when a sender is in the query rather than behind a click.
		let resolved: ResolveResult | undefined;
		if (sender !== '') {
			resolved = await apiFetch<ResolveResult>(token, '/admin/v1/domains:resolve', {
				requestId,
				query: { sender }
			});
		}

		return {
			domains: domains.data,
			backends: backends.data,
			sender,
			resolved,
			canWrite: identity?.can_write === true
		};
	} catch (cause) {
		failWith(cause);
	}
};

export const actions: Actions = {
	create: async ({ locals, request }) => {
		const form = await request.formData();
		const body = {
			name: String(form.get('name') ?? '').trim(),
			backend_id: String(form.get('backend_id') ?? ''),
			include_subdomains: form.get('include_subdomains') === 'on'
		};

		try {
			await apiFetch<Domain>(requireSession(locals).accessToken, '/admin/v1/domains', {
				method: 'POST',
				body,
				requestId: locals.requestId
			});
			return { created: true };
		} catch (cause) {
			if (cause instanceof ApiCallError && [403, 409, 422].includes(cause.status)) {
				return fail(cause.status, { message: cause.message, field: cause.field, values: body });
			}
			failWith(cause);
		}
	},

	remove: async ({ locals, request }) => {
		const form = await request.formData();
		const id = String(form.get('id') ?? '');
		try {
			await apiFetch<void>(
				requireSession(locals).accessToken,
				`/admin/v1/domains/${encodeURIComponent(id)}`,
				{ method: 'DELETE', requestId: locals.requestId }
			);
			return { removed: true };
		} catch (cause) {
			if (cause instanceof ApiCallError && [403, 409].includes(cause.status)) {
				return fail(cause.status, { message: cause.message, values: {} });
			}
			failWith(cause);
		}
	}
};
