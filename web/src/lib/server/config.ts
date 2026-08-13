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
		/**
		 * The OIDC issuer. Endpoints are discovered from it, and it must be the same
		 * value the Go side validates the `iss` claim against (RELAIS_OIDC_ISSUER).
		 */
		issuer: string;
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

	/**
	 * A URL template for searching the log store, with `{query}` where the search
	 * terms go. Empty disables every log link rather than rendering a dead one.
	 *
	 * A template rather than a hostname, because the query syntax belongs to whatever
	 * is deployed — HyperDX, ClickStack, Grafana — and guessing it here would produce
	 * links that open the right tool on the wrong search. Example:
	 *   https://hyperdx.example.com/search?q={query}
	 */
	logsUrlTemplate: string;
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
	// One value, discovered from. The previous design carried the provider's root
	// URL separately because arctic's Authentik class builds the endpoint paths
	// itself — two variables that look alike, cannot be swapped, and produce a 404
	// naming neither when confused. Discovery makes the issuer the only value, and
	// it is the same one relais validates tokens against.
	const issuer = require('RELAIS_WEB_OIDC_ISSUER').replace(/\/+$/, '');
	const clientId = require('RELAIS_WEB_OIDC_CLIENT_ID');
	const clientSecret = require('RELAIS_WEB_OIDC_CLIENT_SECRET');
	const rawKey = require('RELAIS_WEB_SESSION_KEY');

	// A cookie key is not something to default. Generating one at boot would mean
	// every restart signs everybody out, and every replica disagreeing about who is
	// signed in; committing one would mean every reader of this repository can forge
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
		// Without it most providers issue no refresh token, and every session would end
		// abruptly when the short-lived access token expired.
		problems.push('RELAIS_WEB_OIDC_SCOPES must include offline_access to obtain a refresh token');
	}

	const refreshSkewSeconds = positiveInt(env.RELAIS_WEB_REFRESH_SKEW_SECONDS, 60);

	const logsUrlTemplate = (env.RELAIS_WEB_LOGS_URL ?? '').trim();
	if (logsUrlTemplate !== '' && !logsUrlTemplate.includes('{query}')) {
		problems.push(
			'RELAIS_WEB_LOGS_URL must contain {query}, e.g. ' +
				'https://hyperdx.example.com/search?q={query} — without it every log link ' +
				'would open the same unfiltered search'
		);
	}

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
		oidc: { issuer, clientId, clientSecret, scopes },
		sessionKey,
		secureCookie,
		refreshSkewSeconds,
		logsUrlTemplate
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
