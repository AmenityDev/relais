import { apiFetch, failWith, type Identity } from '$lib/server/api';
import type { LayoutServerLoad } from './$types';

// Runs for every page. hooks.server.ts has already guaranteed a session, so the
// only job here is to ask the API who we are acting as.
//
// The identity comes from the API rather than from the token this app decoded,
// because Go is the authority on the role (F6). Deciding it here from the groups
// claim would be a second implementation of the mapping, free to disagree with the
// one that actually enforces it.
export const load: LayoutServerLoad = async ({ locals, depends }) => {
	if (locals.session === undefined) {
		// Unreachable: the hook redirects first. Kept because a future public route
		// added to PUBLIC_PREFIXES would otherwise reach this with no session.
		return { identity: undefined };
	}

	depends('app:identity');

	try {
		const identity = await apiFetch<Identity>(locals.session.accessToken, '/admin/v1/identity', {
			requestId: locals.requestId
		});
		return { identity };
	} catch (cause) {
		failWith(cause);
	}
};
