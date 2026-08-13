import {
	CodeChallengeMethod,
	OAuth2Client,
	generateCodeVerifier,
	generateState,
	OAuth2RequestError
} from 'arctic';
import type { Cookies } from '@sveltejs/kit';
import { config, redirectUri } from './config';
import type { Session } from './session';

// OIDC against any compliant provider, using arctic's OAuth2Client with endpoints
// taken from the issuer's discovery document.
//
// arctic ships a provider class per vendor, and the Authentik one hardcodes
// /application/o/authorize/. Using it meant this application only worked with
// Authentik, and that the configuration had to carry the provider's root URL
// *separately* from its issuer — two values that look alike, cannot be swapped, and
// produce a 404 mentioning neither when confused. Discovery removes both problems:
// the issuer is the single value, and the endpoints come from the provider itself.
//
// arctic is still what performs the exchange, because the brief ruled out
// home-made authentication and this is where a subtle mistake — a missing state
// check, a skipped PKCE verifier — is easy to make and invisible until exploited.

const STATE_COOKIE = 'relais_oidc_state';
const VERIFIER_COOKIE = 'relais_oidc_verifier';
const RETURN_COOKIE = 'relais_oidc_return';

/** Short: this cookie exists only for the round trip to the provider. */
const HANDSHAKE_MAX_AGE = 10 * 60;

/** The endpoints this application needs from a discovery document. */
export interface Endpoints {
	issuer: string;
	authorization: string;
	token: string;
	revocation: string | undefined;
}

// Discovery is fetched once and kept. The document changes when a provider is
// reconfigured, which is a restart-shaped event, and re-fetching it per login would
// put the provider's availability in the path of every sign-in.
let cachedEndpoints: Endpoints | undefined;
let lastFailure: { at: number; message: string } | undefined;

/** How long a discovery failure is remembered, so a down provider is not hammered. */
const DISCOVERY_RETRY_MS = 15_000;

export async function discover(): Promise<Endpoints> {
	if (cachedEndpoints) return cachedEndpoints;

	if (lastFailure !== undefined && Date.now() - lastFailure.at < DISCOVERY_RETRY_MS) {
		throw new LoginError(`the identity provider is unavailable: ${lastFailure.message}`);
	}

	const { oidc } = config();
	const url = `${oidc.issuer}/.well-known/openid-configuration`;

	let document: Record<string, unknown>;
	try {
		const response = await fetch(url, { signal: AbortSignal.timeout(10_000) });
		if (!response.ok) {
			throw new Error(`${url} returned ${response.status}`);
		}
		document = (await response.json()) as Record<string, unknown>;
	} catch (cause) {
		const message = cause instanceof Error ? cause.message : String(cause);
		lastFailure = { at: Date.now(), message };
		throw new LoginError(`OIDC discovery failed: ${message}`);
	}

	const endpoints = readEndpoints(document, oidc.issuer);
	lastFailure = undefined;
	cachedEndpoints = endpoints;
	return endpoints;
}

function readEndpoints(document: Record<string, unknown>, configuredIssuer: string): Endpoints {
	const authorization = document.authorization_endpoint;
	const token = document.token_endpoint;
	const issuer = document.issuer;
	const revocation = document.revocation_endpoint;

	if (typeof authorization !== 'string' || typeof token !== 'string') {
		throw new LoginError(
			'the discovery document has no authorization_endpoint or token_endpoint: ' +
				`is ${configuredIssuer} really an OIDC issuer?`
		);
	}

	// The issuer in the document must match the one configured. A mismatch means the
	// configuration points somewhere that answers for a different issuer, and it is
	// also what the Go side validates the `iss` claim against — so a mismatch here
	// would produce tokens relais rejects, with the failure surfacing one layer away
	// from its cause.
	if (typeof issuer === 'string' && issuer.replace(/\/+$/, '') !== configuredIssuer) {
		throw new LoginError(
			`the provider at ${configuredIssuer} declares its issuer as ${issuer}. ` +
				"Use that value for both RELAIS_WEB_OIDC_ISSUER and the Go side's " +
				'RELAIS_OIDC_ISSUER, or relais will reject every token this app obtains.'
		);
	}

	return {
		issuer: typeof issuer === 'string' ? issuer : configuredIssuer,
		authorization,
		token,
		revocation: typeof revocation === 'string' ? revocation : undefined
	};
}

/** Resets the memoised discovery. Tests only. */
export function resetDiscoveryForTests(): void {
	cachedEndpoints = undefined;
	lastFailure = undefined;
}

function client(): OAuth2Client {
	const { oidc } = config();
	return new OAuth2Client(oidc.clientId, oidc.clientSecret, redirectUri());
}

/**
 * Begins a login, returning the URL to send the browser to.
 *
 * The state and the PKCE verifier are stored in httpOnly cookies rather than in
 * server memory, so a deployment with more than one replica works without sticky
 * sessions or a shared store.
 */
export async function beginLogin(cookies: Cookies, returnTo: string): Promise<URL> {
	const endpoints = await discover();
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

	return client().createAuthorizationURLWithPKCE(
		endpoints.authorization,
		state,
		CodeChallengeMethod.S256,
		verifier,
		config().oidc.scopes
	);
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

	const endpoints = await discover();

	let tokens;
	try {
		tokens = await client().validateAuthorizationCode(endpoints.token, code, verifier);
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
			'the identity provider issued no refresh token: add offline_access to the scopes, ' +
				'and enable it on the provider (Authentik: allow the offline_access scope; ' +
				'Keycloak: the client must not have "Use refresh tokens" disabled)'
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
		const endpoints = await discover();
		const tokens = await client().refreshAccessToken(endpoints.token, session.refreshToken, []);
		const claims = readClaims(tokens.accessToken());
		return {
			accessToken: tokens.accessToken(),
			// A provider may or may not rotate the refresh token; keep the old one when
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
		const endpoints = await discover();
		// Not every provider publishes one, and revocation is optional in OIDC. The
		// local cookie is what actually ends the session here.
		if (endpoints.revocation === undefined) return;
		await client().revokeToken(endpoints.revocation, session.refreshToken);
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
