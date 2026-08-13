import { redirect, type Handle, type HandleServerError } from '@sveltejs/kit';
import { config } from '$lib/server/config';
import { refresh } from '$lib/server/oidc';
import {
	SESSION_COOKIE,
	clearSession,
	decodeSession,
	needsRefresh,
	setSession
} from '$lib/server/session';

// Every request passes through here: the session is decrypted, refreshed if it is
// about to expire, and either attached to locals or absent. Nothing downstream
// reads the cookie itself, so there is exactly one place where a session becomes
// trusted.

/** Paths that must work without a session, or login could never happen. */
const PUBLIC_PREFIXES = ['/auth/login', '/auth/callback', '/auth/error', '/healthz'];

function isPublic(pathname: string): boolean {
	return PUBLIC_PREFIXES.some((prefix) => pathname === prefix || pathname.startsWith(prefix + '/'));
}

export const handle: Handle = async ({ event, resolve }) => {
	// Reuse the caller's id when there is one, so a line in this app's log and a
	// line in the Go log can be joined. Otherwise mint one.
	event.locals.requestId = event.request.headers.get('x-request-id') ?? crypto.randomUUID();

	// A liveness probe must not depend on configuration being valid, or a
	// misconfigured container would look healthy right up to the first real request.
	if (event.url.pathname === '/healthz') {
		return new Response('ok\n', { headers: { 'content-type': 'text/plain' } });
	}

	const raw = event.cookies.get(SESSION_COOKIE);
	if (raw !== undefined) {
		const session = await decodeSession(raw);
		if (session === undefined) {
			// Undecryptable: a rotated key, another deployment's cookie, or tampering.
			// Clearing it stops a redirect loop where the browser keeps presenting a
			// cookie this server will never accept.
			clearSession(event.cookies);
		} else if (needsRefresh(session, nowSeconds(), config().refreshSkewSeconds)) {
			const renewed = await refresh(session);
			if (renewed === undefined) {
				clearSession(event.cookies);
			} else {
				await setSession(event.cookies, renewed);
				event.locals.session = renewed;
			}
		} else {
			event.locals.session = session;
		}
	}

	if (event.locals.session === undefined && !isPublic(event.url.pathname)) {
		// Remember where they were going, so a session that expires mid-task returns
		// them to the page they were on rather than to the dashboard.
		const returnTo = event.url.pathname + event.url.search;
		redirect(303, `/auth/login?return=${encodeURIComponent(returnTo)}`);
	}

	const response = await resolve(event);

	// This app renders an admin interface and loads nothing from anywhere else. A
	// restrictive policy is therefore free, and it is the difference between an XSS
	// that defaces a page and one that exfiltrates what it reads.
	response.headers.set(
		'Content-Security-Policy',
		[
			"default-src 'self'",
			// SvelteKit inlines a small hydration script with a nonce-less hash in dev;
			// in production the bundle is a file, so 'self' suffices. Styles are
			// injected by Vite as <style> in dev and as files in production.
			"script-src 'self' 'unsafe-inline'",
			"style-src 'self' 'unsafe-inline'",
			"img-src 'self' data:",
			"font-src 'self'",
			// No token ever reaches the browser, so there is nothing for the browser to
			// send anywhere. Forbid it outright.
			"connect-src 'self'",
			"form-action 'self'",
			"frame-ancestors 'none'",
			"base-uri 'none'",
			"object-src 'none'"
		].join('; ')
	);
	response.headers.set('X-Content-Type-Options', 'nosniff');
	response.headers.set('Referrer-Policy', 'same-origin');
	response.headers.set('X-Frame-Options', 'DENY');

	return response;
};

/**
 * Logs a server error as JSON and returns a shape the error page can render.
 *
 * The message deliberately does not reach the browser: an unexpected error here
 * may quote an internal hostname or a fragment of a token. The request id does
 * reach it, which is what makes a support conversation possible without leaking
 * anything.
 */
export const handleServerError: HandleServerError = ({ error, event, status, message }) => {
	const requestId = event.locals.requestId ?? 'unknown';

	if (status !== 404) {
		console.error(
			JSON.stringify({
				level: 'ERROR',
				msg: 'unhandled error while rendering',
				request_id: requestId,
				path: event.url.pathname,
				status,
				error: error instanceof Error ? error.message : String(error)
			})
		);
	}

	return {
		message: status === 404 ? 'Not found' : message,
		requestId
	};
};

function nowSeconds(): number {
	return Math.floor(Date.now() / 1000);
}
