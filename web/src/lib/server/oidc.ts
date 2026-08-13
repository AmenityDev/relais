import { Authentik, generateCodeVerifier, generateState, OAuth2RequestError } from 'arctic';
import type { Cookies } from '@sveltejs/kit';
import { config, redirectUri } from './config';
import type { Session } from './session';

// OIDC through Authentik, using arctic rather than hand-rolled OAuth. The brief
// ruled out home-made authentication, and this is the part where a subtle mistake
// (a missing state check, a skipped PKCE verifier) is both easy to make and
// invisible until exploited.

const STATE_COOKIE = 'relais_oidc_state';
const VERIFIER_COOKIE = 'relais_oidc_verifier';
const RETURN_COOKIE = 'relais_oidc_return';

/** Short: this cookie exists only for the round trip to the provider. */
const HANDSHAKE_MAX_AGE = 10 * 60;

function provider(): Authentik {
	const { oidc } = config();
	// oidc.baseUrl is the Authentik root; arctic appends the endpoint paths itself.
	return new Authentik(oidc.baseUrl, oidc.clientId, oidc.clientSecret, redirectUri());
}

/**
 * Begins a login, returning the URL to send the browser to.
 *
 * The state and the PKCE verifier are stored in httpOnly cookies rather than in
 * server memory, so a deployment with more than one replica works without sticky
 * sessions or a shared store.
 */
export function beginLogin(cookies: Cookies, returnTo: string): URL {
	const state = generateState();
	const verifier = generateCodeVerifier();

	const options = {
		path: '/',
		httpOnly: true,
		secure: config().secureCookie,
		sameSite: 'lax' as const,
		maxAge: HANDSHAKE_MAX_AGE
	};
	cookies.set(STATE_COOKIE, state, options);
	cookies.set(VERIFIER_COOKIE, verifier, options);
	cookies.set(RETURN_COOKIE, safeReturnTo(returnTo), options);

	return provider().createAuthorizationURL(state, verifier, config().oidc.scopes);
}

export interface CallbackResult {
	session: Session;
	returnTo: string;
}

/**
 * Completes a login.
 *
 * Throws on any mismatch. In particular the state must be present in both the
 * query and the cookie and must match: without that check, an attacker can have a
 * victim's browser complete a login the attacker started.
 */
export async function completeLogin(cookies: Cookies, url: URL): Promise<CallbackResult> {
	const code = url.searchParams.get('code');
	const state = url.searchParams.get('state');
	const storedState = cookies.get(STATE_COOKIE);
	const verifier = cookies.get(VERIFIER_COOKIE);
	const returnTo = safeReturnTo(cookies.get(RETURN_COOKIE) ?? '/');

	clearHandshake(cookies);

	// The provider reports its own refusals here, and they are not our failure.
	const providerError = url.searchParams.get('error');
	if (providerError !== null) {
		throw new LoginError(
			`the identity provider refused the login: ${providerError}`,
			url.searchParams.get('error_description') ?? undefined
		);
	}

	if (code === null || state === null) {
		throw new LoginError('the callback is missing its code or state');
	}
	if (storedState === undefined || verifier === undefined) {
		// Usually a bookmarked callback URL or a login that took longer than the
		// handshake cookie's lifetime.
		throw new LoginError('this login has expired; start again');
	}
	if (state !== storedState) {
		throw new LoginError('the callback state does not match the one this browser started with');
	}

	let tokens;
	try {
		tokens = await provider().validateAuthorizationCode(code, verifier);
	} catch (cause) {
		if (cause instanceof OAuth2RequestError) {
			throw new LoginError(`the identity provider rejected the code: ${cause.code}`);
		}
		throw new LoginError('the identity provider could not be reached');
	}

	if (!tokens.hasRefreshToken()) {
		// Without one, the session would end the moment the short-lived access token
		// expired, which reads to a user as being logged out at random.
		throw new LoginError(
			'the identity provider issued no refresh token: add offline_access to the scopes ' +
				'and allow it on the Authentik provider'
		);
	}

	const claims = readClaims(tokens.accessToken());

	return {
		session: {
			accessToken: tokens.accessToken(),
			refreshToken: tokens.refreshToken(),
			expiresAt: Math.floor(tokens.accessTokenExpiresAt().getTime() / 1000),
			subject: claims.subject,
			groups: claims.groups
		},
		returnTo
	};
}

/** Exchanges a refresh token for a new access token. */
export async function refresh(session: Session): Promise<Session | undefined> {
	try {
		const tokens = await provider().refreshAccessToken(session.refreshToken);
		const claims = readClaims(tokens.accessToken());
		return {
			accessToken: tokens.accessToken(),
			// Authentik may or may not rotate the refresh token; keep the old one when
			// it does not, or the next refresh would have nothing to present.
			refreshToken: tokens.hasRefreshToken() ? tokens.refreshToken() : session.refreshToken,
			expiresAt: Math.floor(tokens.accessTokenExpiresAt().getTime() / 1000),
			subject: claims.subject,
			groups: claims.groups
		};
	} catch {
		// A refusal here means the session is over: revoked, expired, or the user was
		// removed. There is nothing to retry.
		return undefined;
	}
}

/** Best-effort revocation at sign-out. */
export async function revoke(session: Session): Promise<void> {
	try {
		await provider().revokeToken(session.refreshToken);
	} catch {
		// The local cookie is cleared regardless. A provider that cannot be reached
		// must not stop someone signing out.
	}
}

export class LoginError extends Error {
	constructor(
		message: string,
		readonly detail?: string
	) {
		super(message);
		this.name = 'LoginError';
	}
}

export function clearHandshake(cookies: Cookies): void {
	for (const name of [STATE_COOKIE, VERIFIER_COOKIE, RETURN_COOKIE]) {
		cookies.delete(name, { path: '/' });
	}
}

/**
 * Reads the claims this app needs from the access token.
 *
 * The signature is NOT verified here, and that is deliberate: the token came
 * directly from the provider's token endpoint over TLS, and the party that
 * actually enforces it is Go, which validates it against the JWKS on every call.
 * Verifying it a second time in TypeScript would add a second implementation of
 * the check that matters, with its own bugs, for no additional guarantee.
 *
 * These values are used only to display a name and to size the cookie. Every
 * authorisation decision is the API's.
 */
function readClaims(accessToken: string): { subject: string; groups: string[] } {
	const parts = accessToken.split('.');
	if (parts.length !== 3 || parts[1] === undefined) {
		throw new LoginError(
			'the access token is not a JWT: set a Signing Key on the Authentik provider, ' +
				'otherwise it issues an opaque token that relais cannot validate'
		);
	}

	let payload: Record<string, unknown>;
	try {
		payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as Record<
			string,
			unknown
		>;
	} catch {
		throw new LoginError('the access token payload could not be read');
	}

	const subject = typeof payload.sub === 'string' ? payload.sub : '';
	if (subject === '') throw new LoginError('the access token carries no subject');

	const raw = payload.groups;
	const groups = Array.isArray(raw) ? raw.filter((g): g is string => typeof g === 'string') : [];

	return { subject, groups };
}

/**
 * Confines a post-login redirect to this app.
 *
 * Without this, `/auth/login?return=https://evil.example` would turn the login
 * into an open redirect that borrows this app's credibility.
 */
function safeReturnTo(value: string): string {
	if (!value.startsWith('/') || value.startsWith('//')) return '/';
	return value;
}
