import { redirect, type RequestHandler } from '@sveltejs/kit';
import { revoke } from '$lib/server/oidc';
import { clearSession } from '$lib/server/session';

// POST, not GET: a link that signs someone out can be triggered by any page that
// embeds it, and by a prefetch. A form post cannot.
export const POST: RequestHandler = async ({ cookies, locals }) => {
	if (locals.session !== undefined) {
		await revoke(locals.session);
	}
	clearSession(cookies);
	redirect(303, '/auth/error?reason=signed+out');
};
