import { beforeEach, describe, expect, it, vi } from 'vitest';

const { testEnv } = vi.hoisted(() => ({ testEnv: {} as Record<string, string | undefined> }));
vi.mock('$env/dynamic/private', () => ({ env: testEnv }));

const { config, redirectUri, resetConfigForTests } = await import('./config');

const VALID = {
	RELAIS_WEB_API_URL: 'http://relais:8081',
	RELAIS_WEB_ORIGIN: 'https://mail-admin.example.com',
	RELAIS_WEB_OIDC_BASE_URL: 'https://auth.example.com',
	RELAIS_WEB_OIDC_CLIENT_ID: 'client',
	RELAIS_WEB_OIDC_CLIENT_SECRET: 'secret',
	RELAIS_WEB_SESSION_KEY: Buffer.alloc(32, 3).toString('base64')
};

function setEnv(overrides: Record<string, string | undefined> = {}): void {
	for (const name of Object.keys(testEnv)) delete testEnv[name];
	Object.assign(testEnv, VALID, overrides);
	for (const [name, value] of Object.entries(overrides)) {
		if (value === undefined) delete testEnv[name];
	}
	resetConfigForTests();
}

beforeEach(() => setEnv());

describe('configuration', () => {
	it('accepts a complete environment', () => {
		const loaded = config();
		expect(loaded.apiBaseUrl).toBe('http://relais:8081');
		expect(loaded.sessionKey).toHaveLength(32);
		expect(loaded.secureCookie).toBe(true);
	});

	it('reports every problem at once', () => {
		// One restart per mistake is the failure mode this avoids, and it is the same
		// choice the Go side makes for its own configuration.
		setEnv({
			RELAIS_WEB_API_URL: undefined,
			RELAIS_WEB_OIDC_CLIENT_ID: undefined,
			RELAIS_WEB_SESSION_KEY: undefined
		});

		let message = '';
		try {
			config();
		} catch (cause) {
			message = cause instanceof Error ? cause.message : String(cause);
		}

		expect(message).toContain('RELAIS_WEB_API_URL');
		expect(message).toContain('RELAIS_WEB_OIDC_CLIENT_ID');
		expect(message).toContain('RELAIS_WEB_SESSION_KEY');
	});

	it('names the command that generates a session key', () => {
		// The person who meets this error is deploying, not reading source.
		setEnv({ RELAIS_WEB_SESSION_KEY: undefined });
		expect(() => config()).toThrow(/randomBytes\(32\)/);
	});

	it.each([
		['not base64', 'not-base-64-at-all!!'],
		['a truncated key', Buffer.alloc(16, 4).toString('base64')],
		['an over-long key', Buffer.alloc(64, 4).toString('base64')]
	])('refuses %s', (_name, key) => {
		setEnv({ RELAIS_WEB_SESSION_KEY: key });
		expect(() => config()).toThrow(/RELAIS_WEB_SESSION_KEY/);
	});

	it('refuses non-canonical base64 rather than silently truncating', () => {
		// Buffer.from is lenient and would accept this, producing a key that works
		// until another replica has to decrypt what this one wrote.
		setEnv({ RELAIS_WEB_SESSION_KEY: Buffer.alloc(32, 5).toString('base64') + 'junk' });
		expect(() => config()).toThrow(/RELAIS_WEB_SESSION_KEY/);
	});

	it('requires offline_access, because without it sessions end at random', () => {
		setEnv({ RELAIS_WEB_OIDC_SCOPES: 'openid profile email' });
		expect(() => config()).toThrow(/offline_access/);
	});

	it('requires openid', () => {
		setEnv({ RELAIS_WEB_OIDC_SCOPES: 'profile offline_access' });
		expect(() => config()).toThrow(/openid/);
	});

	it('defaults the scopes to a working set', () => {
		expect(config().oidc.scopes).toEqual(['openid', 'profile', 'email', 'offline_access']);
	});

	it('accepts scopes separated by commas or spaces', () => {
		setEnv({ RELAIS_WEB_OIDC_SCOPES: 'openid, profile,offline_access' });
		expect(config().oidc.scopes).toEqual(['openid', 'profile', 'offline_access']);
	});

	describe('the insecure cookie escape hatch', () => {
		it('is allowed on loopback', () => {
			setEnv({
				RELAIS_WEB_ORIGIN: 'http://localhost:5173',
				RELAIS_WEB_INSECURE_COOKIE: 'true'
			});
			expect(config().secureCookie).toBe(false);
		});

		it('is refused on a real origin', () => {
			// An admin session cookie over plain HTTP is readable by anything on the
			// path. The convenience only makes sense where there is no path.
			setEnv({
				RELAIS_WEB_ORIGIN: 'https://mail-admin.example.com',
				RELAIS_WEB_INSECURE_COOKIE: 'true'
			});
			expect(() => config()).toThrow(/loopback/);
		});

		it('is off unless spelled exactly', () => {
			setEnv({ RELAIS_WEB_INSECURE_COOKIE: 'yes' });
			expect(config().secureCookie).toBe(true);
		});
	});

	it('strips trailing slashes so a URL cannot be doubled', () => {
		setEnv({
			RELAIS_WEB_API_URL: 'http://relais:8081/',
			RELAIS_WEB_ORIGIN: 'https://mail-admin.example.com//'
		});
		expect(config().apiBaseUrl).toBe('http://relais:8081');
		expect(redirectUri()).toBe('https://mail-admin.example.com/auth/callback');
	});

	it('derives the redirect URI from the origin', () => {
		// Two variables that must agree are one variable. A mismatch here is refused by
		// the provider with an error that names neither side.
		expect(redirectUri()).toBe('https://mail-admin.example.com/auth/callback');
	});

	it('falls back to a sane refresh skew', () => {
		setEnv({ RELAIS_WEB_REFRESH_SKEW_SECONDS: 'soon' });
		expect(config().refreshSkewSeconds).toBe(60);
		setEnv({ RELAIS_WEB_REFRESH_SKEW_SECONDS: '-5' });
		expect(config().refreshSkewSeconds).toBe(60);
		setEnv({ RELAIS_WEB_REFRESH_SKEW_SECONDS: '120' });
		expect(config().refreshSkewSeconds).toBe(120);
	});
});

describe('the Authentik base URL', () => {
	it('refuses the issuer URL, which is the mistake that costs an afternoon', () => {
		// arctic appends /application/o/authorize/ to this value. Given the issuer, the
		// result is .../application/o/relais/application/o/authorize/ — a 404 from
		// Authentik whose message mentions neither variable.
		setEnv({ RELAIS_WEB_OIDC_BASE_URL: 'https://auth.example.com/application/o/relais' });
		expect(() => config()).toThrow(/must be the Authentik root/);
	});

	it('names the Go-side variable so the two are not confused', () => {
		setEnv({ RELAIS_WEB_OIDC_BASE_URL: 'https://auth.example.com/application/o/relais/' });
		expect(() => config()).toThrow(/RELAIS_ADMIN_OIDC_ISSUER/);
	});

	it('accepts the root', () => {
		setEnv({ RELAIS_WEB_OIDC_BASE_URL: 'https://auth.example.com' });
		expect(config().oidc.baseUrl).toBe('https://auth.example.com');
	});
});
