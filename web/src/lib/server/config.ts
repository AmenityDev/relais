import { env } from '$env/dynamic/private';
import { fromBase64 } from './bytes';

// Configuration is read at first use and validated all at once, so a
// misconfigured deployment reports every problem rather than one per restart.
//
// $env/dynamic/private rather than $env/static/private: this container is built
// once and configured by the platform, so the values cannot be baked in at build
// time. The `private` half of that name is enforced by SvelteKit — importing this
// module from client code fails the build, which is what makes the guarantee in
// F2 mechanical rather than a matter of discipline.

export interface Config {
	/** Where the Go admin API listens. Never reachable from a browser. */
	apiBaseUrl: string;
	/** The public origin of this app, used to build the OIDC redirect URI. */
	origin: string;

	oidc: {
		/** The Authentik root, e.g. https://auth.example.com. NOT the issuer URL. */
		baseUrl: string;
		clientId: string;
		clientSecret: string;
		scopes: string[];
	};

	/** 32 bytes, base64. Encrypts the session cookie. */
	sessionKey: Uint8Array<ArrayBuffer>;
	/** Set Secure on the session cookie. Off only for plain-HTTP local dev. */
	secureCookie: boolean;

	/** How long before expiry to refresh the access token, in seconds. */
	refreshSkewSeconds: number;
}

let cached: Config | undefined;

export function config(): Config {
	if (cached) return cached;

	const problems: string[] = [];

	const require = (name: string): string => {
		const value = (env[name] ?? '').trim();
		if (value === '') problems.push(`${name} is required`);
		return value;
	};

	const apiBaseUrl = require('RELAIS_WEB_API_URL').replace(/\/+$/, '');
	const origin = require('RELAIS_WEB_ORIGIN').replace(/\/+$/, '');
	const baseUrl = require('RELAIS_WEB_OIDC_BASE_URL').replace(/\/+$/, '');
	// The trap this guard exists for: Authentik's *issuer* is
	// https://auth.example.com/application/o/<slug>/ and its *endpoints* are at
	// https://auth.example.com/application/o/authorize/. arctic builds the second
	// from a root URL, so passing the issuer produces
	// .../application/o/<slug>/application/o/authorize/ — a 404 from Authentik that
	// says nothing about the cause. Go needs the issuer; this app needs the root.
	if (baseUrl.includes('/application/o/')) {
		problems.push(
			'RELAIS_WEB_OIDC_BASE_URL must be the Authentik root (https://auth.example.com), ' +
				'not the issuer URL: the OIDC endpoint paths are appended to it. The issuer, ' +
				'with /application/o/<slug>/, is what the Go side validates tokens against ' +
				'(RELAIS_ADMIN_OIDC_ISSUER).'
		);
	}
	const clientId = require('RELAIS_WEB_OIDC_CLIENT_ID');
	const clientSecret = require('RELAIS_WEB_OIDC_CLIENT_SECRET');
	const rawKey = require('RELAIS_WEB_SESSION_KEY');

	// A cookie key is not something to default. Generating one at boot would mean
	// every restart signs everybody out, and every replica disagreeing about who is
	// signed in; committing one would mean every reader of the repository can forge
	// a session. So it is required, exactly as the Go side requires its own keys.
	let sessionKey = new Uint8Array(0);
	if (rawKey !== '') {
		try {
			sessionKey = fromBase64(rawKey);
		} catch {
			problems.push('RELAIS_WEB_SESSION_KEY is not valid base64');
		}
		if (sessionKey.length !== 0 && sessionKey.length !== 32) {
			problems.push(
				`RELAIS_WEB_SESSION_KEY must decode to 32 bytes for AES-256-GCM, got ${sessionKey.length}`
			);
		}
	}

	// Secure defaults on, and is only ever turned off deliberately. A session
	// cookie sent over plain HTTP is readable by anything on the path, so the
	// insecure case has to be asked for by name.
	const secureCookie = (env.RELAIS_WEB_INSECURE_COOKIE ?? '').trim() !== 'true';
	if (
		!secureCookie &&
		!origin.startsWith('http://localhost') &&
		!origin.startsWith('http://127.')
	) {
		problems.push(
			'RELAIS_WEB_INSECURE_COOKIE is only allowed with a loopback origin: ' +
				'an admin session cookie must not travel over plain HTTP'
		);
	}

	const scopes = splitScopes(env.RELAIS_WEB_OIDC_SCOPES);
	if (!scopes.includes('openid')) problems.push('RELAIS_WEB_OIDC_SCOPES must include openid');
	if (!scopes.includes('offline_access')) {
		// Without it Authentik issues no refresh token, and every session would end
		// abruptly when the short-lived access token expired.
		problems.push('RELAIS_WEB_OIDC_SCOPES must include offline_access to obtain a refresh token');
	}

	const refreshSkewSeconds = positiveInt(env.RELAIS_WEB_REFRESH_SKEW_SECONDS, 60);

	if (problems.length > 0) {
		throw new Error(
			`relais-web is misconfigured:\n  - ${problems.join('\n  - ')}\n\n` +
				'Generate a session key with:\n' +
				"  node -e \"console.log(require('crypto').randomBytes(32).toString('base64'))\"\n"
		);
	}

	cached = {
		apiBaseUrl,
		origin,
		oidc: { baseUrl, clientId, clientSecret, scopes },
		sessionKey,
		secureCookie,
		refreshSkewSeconds
	};
	return cached;
}

/** The OIDC redirect URI, derived from the origin so the two cannot disagree. */
export function redirectUri(): string {
	return `${config().origin}/auth/callback`;
}

function splitScopes(raw: string | undefined): string[] {
	const value = (raw ?? '').trim();
	if (value === '') return ['openid', 'profile', 'email', 'offline_access'];
	return value.split(/[\s,]+/).filter((s) => s !== '');
}

function positiveInt(raw: string | undefined, fallback: number): number {
	const parsed = Number.parseInt((raw ?? '').trim(), 10);
	return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/** Resets the memoised configuration. Tests only. */
export function resetConfigForTests(): void {
	cached = undefined;
}
