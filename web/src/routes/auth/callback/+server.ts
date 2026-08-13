import { redirect, type RequestHandler } from '@sveltejs/kit';
import { LoginError, clearHandshake, completeLogin } from '$lib/server/oidc';
import { setSession } from '$lib/server/session';

export const GET: RequestHandler = async ({ cookies, url, locals }) => {
	try {
		const { session, returnTo } = await completeLogin(cookies, url);
		await setSession(cookies, session);
		redirect(303, returnTo);
	} catch (cause) {
		// A redirect is thrown, so it must pass through untouched.
		if (isRedirect(cause)) throw cause;

		clearHandshake(cookies);

		if (cause instanceof LoginError) {
			console.warn(
				JSON.stringify({
					level: 'WARN',
					msg: 'login failed',
					request_id: locals.requestId,
					reason: cause.message,
					detail: cause.detail
				})
			);
			redirect(303, `/auth/error?reason=${encodeURIComponent(cause.message)}`);
		}
		throw cause;
	}
};

function isRedirect(value: unknown): boolean {
	return typeof value === 'object' && value !== null && 'status' in value && 'location' in value;
}
