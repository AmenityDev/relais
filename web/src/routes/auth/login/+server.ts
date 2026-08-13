import { redirect, type RequestHandler } from '@sveltejs/kit';
import { beginLogin } from '$lib/server/oidc';

export const GET: RequestHandler = ({ cookies, url, locals }) => {
	// Already signed in: nothing to do. Starting a second handshake would replace a
	// working session with a fresh one for no reason.
	if (locals.session !== undefined) {
		redirect(303, '/');
	}

	const authorizationUrl = beginLogin(cookies, url.searchParams.get('return') ?? '/');
	redirect(303, authorizationUrl.toString());
};
