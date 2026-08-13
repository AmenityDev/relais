import { fail } from '@sveltejs/kit';
import {
	ApiCallError,
	apiFetch,
	failWith,
	type Credential,
	type Pattern,
	type PatternTest,
	type PatternValidation
} from '$lib/server/api';
import { requireSession } from '$lib/server/session';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals, params, parent }) => {
	const { identity } = await parent();
	const token = requireSession(locals).accessToken;
	const requestId = locals.requestId;
	const id = encodeURIComponent(params.id);

	try {
		const [credential, patterns] = await Promise.all([
			apiFetch<Credential>(token, `/admin/v1/credentials/${id}`, { requestId }),
			apiFetch<{ data: Pattern[] }>(token, `/admin/v1/credentials/${id}/patterns`, { requestId })
		]);
		return { credential, patterns: patterns.data, canWrite: identity?.can_write === true };
	} catch (cause) {
		failWith(cause);
	}
};

export const actions: Actions = {
	// The dry runs (F5). These exist so the grammar is never reimplemented in
	// TypeScript: the answer comes from the same code that enforces it at send time.
	validate: async ({ locals, request }) => {
		const form = await request.formData();
		const pattern = String(form.get('pattern') ?? '').trim();
		try {
			const validation = await apiFetch<PatternValidation>(
				requireSession(locals).accessToken,
				'/admin/v1/patterns:validate',
				{ method: 'POST', body: { pattern }, requestId: locals.requestId }
			);
			return { validation, pattern };
		} catch (cause) {
			failWith(cause);
		}
	},

	test: async ({ locals, params, request }) => {
		const form = await request.formData();
		const address = String(form.get('address') ?? '').trim();
		try {
			const test = await apiFetch<PatternTest>(
				requireSession(locals).accessToken,
				`/admin/v1/credentials/${encodeURIComponent(params.id)}/patterns:test`,
				{ method: 'POST', body: { address }, requestId: locals.requestId }
			);
			return { test };
		} catch (cause) {
			if (cause instanceof ApiCallError && cause.status === 422) {
				return fail(422, { message: cause.message, values: {} });
			}
			failWith(cause);
		}
	},

	add: async ({ locals, params, request }) => {
		const form = await request.formData();
		const patterns = String(form.get('patterns') ?? '')
			.split(/[\s,]+/)
			.filter((p) => p !== '');
		try {
			await apiFetch<{ data: Pattern[] }>(
				requireSession(locals).accessToken,
				`/admin/v1/credentials/${encodeURIComponent(params.id)}/patterns`,
				{ method: 'POST', body: { patterns }, requestId: locals.requestId }
			);
			return { added: true };
		} catch (cause) {
			if (cause instanceof ApiCallError && [403, 422].includes(cause.status)) {
				return fail(cause.status, {
					message: cause.message,
					values: { patterns: patterns.join('\n') }
				});
			}
			failWith(cause);
		}
	},

	remove: async ({ locals, params, request }) => {
		const form = await request.formData();
		const patternId = String(form.get('pattern_id') ?? '');
		try {
			await apiFetch<void>(
				requireSession(locals).accessToken,
				`/admin/v1/credentials/${encodeURIComponent(params.id)}/patterns/${encodeURIComponent(patternId)}`,
				{ method: 'DELETE', requestId: locals.requestId }
			);
			return { removed: true };
		} catch (cause) {
			if (cause instanceof ApiCallError && [403, 404].includes(cause.status)) {
				return fail(cause.status, { message: cause.message, values: {} });
			}
			failWith(cause);
		}
	}
};
