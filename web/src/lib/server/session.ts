import { error, type Cookies } from '@sveltejs/kit';
import { fromBase64Url, toBase64Url } from './bytes';
import { config } from './config';

// The session lives in one encrypted cookie (F3). The browser holds a token it
// cannot read: an XSS in this app cannot steal an access token, and the refresh
// token never leaves the server's own ciphertext.
//
// AES-256-GCM, so the cookie is both confidential and authenticated. Signing
// alone would be enough to stop forgery but would leave the access token readable
// by anyone who can see the cookie — including a browser extension, or a log that
// captured a request header.

export const SESSION_COOKIE = 'relais_session';

/** How large a cookie may get before it is worth a warning. See the note below. */
const COOKIE_WARN_BYTES = 3500;

/**
 * The hard ceiling browsers enforce, including the name and the attributes.
 * Exceeding it does not error: the browser silently drops the cookie, and the
 * user sees an endless redirect to the login page instead of an error. That
 * silence is the reason for the guard rail.
 */
const COOKIE_LIMIT_BYTES = 4096;

export interface Session {
	accessToken: string;
	refreshToken: string;
	/** Access token expiry, in seconds since the epoch. */
	expiresAt: number;
	subject: string;
	groups: string[];
}

/** The JSON actually stored, with short keys because every byte is in the budget. */
interface StoredSession {
	a: string;
	r: string;
	e: number;
	s: string;
	g: string[];
}

export async function encodeSession(session: Session): Promise<string> {
	const stored: StoredSession = {
		a: session.accessToken,
		r: session.refreshToken,
		e: session.expiresAt,
		s: session.subject,
		g: session.groups
	};

	const plaintext = new TextEncoder().encode(JSON.stringify(stored));
	const key = await importKey();
	const nonce = crypto.getRandomValues(new Uint8Array(12));
	const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plaintext);

	const combined = new Uint8Array(nonce.length + ciphertext.byteLength);
	combined.set(nonce, 0);
	combined.set(new Uint8Array(ciphertext), nonce.length);

	return toBase64Url(combined);
}

export async function decodeSession(value: string): Promise<Session | undefined> {
	try {
		const combined = fromBase64Url(value);
		// 12-byte nonce + 16-byte tag: anything shorter cannot be a valid message,
		// and rejecting it here keeps a malformed cookie from reaching the AEAD.
		if (combined.length <= 28) return undefined;

		const nonce = combined.subarray(0, 12);
		const ciphertext = combined.subarray(12);
		const key = await importKey();
		const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ciphertext);

		const stored = JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
		return parseStored(stored);
	} catch {
		// A cookie that fails to decrypt is one this key did not write: a rotated
		// key, a tampered value, or another deployment's. All three mean the same
		// thing to the caller — there is no session — and none of them is worth
		// distinguishing to an attacker.
		return undefined;
	}
}

function parseStored(value: unknown): Session | undefined {
	if (typeof value !== 'object' || value === null) return undefined;
	const stored = value as Partial<StoredSession>;

	if (
		typeof stored.a !== 'string' ||
		typeof stored.r !== 'string' ||
		typeof stored.e !== 'number' ||
		typeof stored.s !== 'string' ||
		!Array.isArray(stored.g)
	) {
		return undefined;
	}
	if (stored.a === '' || stored.s === '') return undefined;

	return {
		accessToken: stored.a,
		refreshToken: stored.r,
		expiresAt: stored.e,
		subject: stored.s,
		groups: stored.g.filter((g): g is string => typeof g === 'string')
	};
}

/**
 * Writes the session cookie, and warns when it approaches the size at which
 * browsers start dropping it.
 *
 * The measured size on the target Authentik instance is about 2683 bytes, which
 * leaves roughly 1300 to spare. That headroom is not unlimited: it shrinks with
 * every claim added to the access token, and group membership is the claim most
 * likely to grow. Drift has to become visible before it breaks, because what
 * breaks is silent — the browser discards the cookie and the operator sees a login
 * loop with nothing in the logs to explain it.
 */
export async function setSession(cookies: Cookies, session: Session): Promise<void> {
	const value = await encodeSession(session);
	const total = cookieSize(SESSION_COOKIE, value);

	if (total > COOKIE_LIMIT_BYTES) {
		// Refusing is better than writing a cookie the browser will drop: this way
		// the failure names itself.
		throw new Error(
			`the session cookie is ${total} bytes, over the ${COOKIE_LIMIT_BYTES}-byte limit ` +
				'browsers enforce. The access token or the group list has grown too large; ' +
				'reduce the claims Authentik puts in the token, or move to a server-side session store.'
		);
	}
	if (total > COOKIE_WARN_BYTES) {
		console.warn(
			JSON.stringify({
				level: 'WARN',
				msg: 'session cookie is approaching the browser size limit',
				bytes: total,
				limit: COOKIE_LIMIT_BYTES,
				groups: session.groups.length,
				hint: 'trim the claims in the Authentik property mapping; see docs/FRONTEND.md F3'
			})
		);
	}

	cookies.set(SESSION_COOKIE, value, {
		path: '/',
		httpOnly: true,
		secure: config().secureCookie,
		// Lax rather than Strict: the OIDC provider redirects back with a top-level
		// GET, and Strict would withhold the cookie on that navigation, so the
		// callback would never see the session it just created.
		sameSite: 'lax',
		// No maxAge: a session cookie that dies with the browser session. The
		// refresh token's own lifetime is the real bound, and it is enforced by
		// Authentik rather than by a number this app made up.
		maxAge: undefined
	});
}

export function clearSession(cookies: Cookies): void {
	cookies.delete(SESSION_COOKIE, { path: '/' });
}

/**
 * The on-the-wire size of a cookie, including the name and the attributes that
 * count against the limit. Browsers apply the limit to the whole Set-Cookie pair,
 * not to the value alone, so measuring only the value would overstate the
 * headroom.
 */
export function cookieSize(name: string, value: string): number {
	const attributes = '; Path=/; HttpOnly; Secure; SameSite=Lax';
	return new TextEncoder().encode(`${name}=${value}${attributes}`).length;
}

/** True when the access token is expired or close enough that it should be renewed. */
export function needsRefresh(session: Session, nowSeconds: number, skewSeconds: number): boolean {
	return session.expiresAt - skewSeconds <= nowSeconds;
}

async function importKey(): Promise<CryptoKey> {
	return crypto.subtle.importKey('raw', config().sessionKey, { name: 'AES-GCM' }, false, [
		'encrypt',
		'decrypt'
	]);
}

/**
 * Returns the session, or fails loudly.
 *
 * hooks.server.ts guarantees one on every non-public route, so this never fires in
 * practice — but a non-null assertion at each call site would be a promise the
 * compiler stops checking, and the day a route is added to PUBLIC_PREFIXES the
 * failure would be a property access on undefined rather than a clear 401.
 */
export function requireSession(locals: App.Locals): Session {
	if (locals.session === undefined) {
		error(401, { message: 'Your session has ended. Sign in again.', code: 'no_session' });
	}
	return locals.session;
}
