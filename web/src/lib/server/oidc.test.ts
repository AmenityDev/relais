import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { testEnv } = vi.hoisted(() => ({ testEnv: {} as Record<string, string | undefined> }));
vi.mock('$env/dynamic/private', () => ({ env: testEnv }));

const { resetConfigForTests } = await import('./config');
const { LoginError, beginLogin, completeLogin, discover, resetDiscoveryForTests } =
	await import('./oidc');

const ISSUER = 'https://auth.example.com/realms/relais';

/** A discovery document shaped like a real provider's. */
function discoveryDocument(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		issuer: ISSUER,
		authorization_endpoint: `${ISSUER}/protocol/openid-connect/auth`,
		token_endpoint: `${ISSUER}/protocol/openid-connect/token`,
		revocation_endpoint: `${ISSUER}/protocol/openid-connect/revoke`,
		jwks_uri: `${ISSUER}/protocol/openid-connect/certs`,
		...overrides
	};
}

/** Serves a discovery document, and records what was fetched. */
function stubDiscovery(document: Record<string, unknown> = discoveryDocument()) {
	const calls: string[] = [];
	vi.stubGlobal(
		'fetch',
		vi.fn((input: URL | string) => {
			calls.push(String(input));
			return Promise.resolve(
				new Response(JSON.stringify(document), {
					status: 200,
					headers: { 'content-type': 'application/json' }
				})
			);
		})
	);
	return calls;
}

// A minimal Cookies stand-in. The real one belongs to a request; these tests are
// about what the handshake stores and checks, not about SvelteKit's plumbing.
function fakeCookies(initial: Record<string, string> = {}) {
	const store = new Map(Object.entries(initial));
	return {
		store,
		cookies: {
			get: (name: string) => store.get(name),
			set: (name: string, value: string) => void store.set(name, value),
			delete: (name: string) => void store.delete(name),
			getAll: () => [...store].map(([name, value]) => ({ name, value })),
			serialize: () => ''
		}
	};
}

beforeEach(() => {
	for (const name of Object.keys(testEnv)) delete testEnv[name];
	Object.assign(testEnv, {
		RELAIS_WEB_API_URL: 'http://relais:8081',
		RELAIS_WEB_ORIGIN: 'https://mail-admin.example.com',
		RELAIS_WEB_OIDC_ISSUER: 'https://auth.example.com/realms/relais',
		RELAIS_WEB_OIDC_CLIENT_ID: 'client-id',
		RELAIS_WEB_OIDC_CLIENT_SECRET: 'client-secret',
		RELAIS_WEB_SESSION_KEY: Buffer.alloc(32, 6).toString('base64')
	});
	resetConfigForTests();
	resetDiscoveryForTests();
	stubDiscovery();
});

afterEach(() => vi.unstubAllGlobals());

describe('discovery', () => {
	it('reads the endpoints from the issuer', async () => {
		const calls = stubDiscovery();
		const endpoints = await discover();

		expect(calls).toEqual([`${ISSUER}/.well-known/openid-configuration`]);
		expect(endpoints.authorization).toBe(`${ISSUER}/protocol/openid-connect/auth`);
		expect(endpoints.token).toBe(`${ISSUER}/protocol/openid-connect/token`);
	});

	it('fetches once and keeps the result', async () => {
		// A provider outage must not sit in the path of every sign-in.
		const calls = stubDiscovery();
		await discover();
		await discover();
		await discover();
		expect(calls).toHaveLength(1);
	});

	it('refuses a document whose issuer disagrees with the configuration', async () => {
		// The Go side validates the `iss` claim against its own configured issuer. A
		// mismatch here yields tokens relais rejects, and the failure would surface a
		// layer away from its cause.
		resetDiscoveryForTests();
		stubDiscovery(discoveryDocument({ issuer: 'https://auth.example.com/realms/other' }));
		await expect(discover()).rejects.toThrow(/declares its issuer as/);
	});

	it('names both variables in that message', async () => {
		resetDiscoveryForTests();
		stubDiscovery(discoveryDocument({ issuer: 'https://elsewhere.example' }));
		await expect(discover()).rejects.toThrow(/RELAIS_OIDC_ISSUER/);
	});

	it('refuses a document that is not an OIDC configuration', async () => {
		resetDiscoveryForTests();
		stubDiscovery({ hello: 'world' });
		await expect(discover()).rejects.toThrow(/really an OIDC issuer/);
	});

	it('reports an unreachable provider without caching a success', async () => {
		resetDiscoveryForTests();
		vi.stubGlobal(
			'fetch',
			vi.fn(() => Promise.reject(new Error('ECONNREFUSED')))
		);
		await expect(discover()).rejects.toThrow(/discovery failed/);

		// The failure is remembered briefly, so a down provider is not asked once per
		// request — but it must never be remembered as a success.
		await expect(discover()).rejects.toThrow(/unavailable/);
	});

	it('tolerates a provider that publishes no revocation endpoint', async () => {
		resetDiscoveryForTests();
		const document = discoveryDocument();
		delete document.revocation_endpoint;
		stubDiscovery(document);
		expect((await discover()).revocation).toBeUndefined();
	});
});

describe('beginLogin', () => {
	it('sends the browser to the issuer with PKCE and a state', async () => {
		const { cookies, store } = fakeCookies();
		const url = await beginLogin(cookies as never, '/backends');

		expect(url.origin).toBe('https://auth.example.com');
		expect(url.pathname).toBe('/realms/relais/protocol/openid-connect/auth');
		expect(url.searchParams.get('client_id')).toBe('client-id');
		expect(url.searchParams.get('response_type')).toBe('code');
		expect(url.searchParams.get('code_challenge_method')).toBe('S256');
		expect(url.searchParams.get('code_challenge')).toBeTruthy();
		expect(url.searchParams.get('redirect_uri')).toBe(
			'https://mail-admin.example.com/auth/callback'
		);
		expect(url.searchParams.get('scope')).toContain('offline_access');

		// Both halves of the handshake are stored, not held in server memory, so more
		// than one replica works without sticky sessions.
		expect(store.get('relais_oidc_state')).toBe(url.searchParams.get('state'));
		expect(store.get('relais_oidc_verifier')).toBeTruthy();
	});

	it('stores the handshake cookies as httpOnly with a short life', async () => {
		const options: Record<string, unknown>[] = [];
		const cookies = {
			set: (_n: string, _v: string, opts: Record<string, unknown>) => options.push(opts),
			get: () => undefined,
			delete: () => undefined
		};

		await beginLogin(cookies as never, '/');

		expect(options).toHaveLength(3);
		for (const opts of options) {
			expect(opts).toMatchObject({ httpOnly: true, secure: true, sameSite: 'lax' });
			expect(opts.maxAge).toBe(600);
		}
	});

	it('mints a fresh state and verifier for each attempt', async () => {
		const first = fakeCookies();
		const second = fakeCookies();
		await beginLogin(first.cookies as never, '/');
		await beginLogin(second.cookies as never, '/');

		expect(first.store.get('relais_oidc_state')).not.toBe(second.store.get('relais_oidc_state'));
		expect(first.store.get('relais_oidc_verifier')).not.toBe(
			second.store.get('relais_oidc_verifier')
		);
	});

	describe('the post-login redirect', () => {
		it.each([
			['/messages?status=failed', '/messages?status=failed'],
			['/', '/']
		])('keeps an internal path (%s)', async (input, expected) => {
			const { cookies, store } = fakeCookies();
			await beginLogin(cookies as never, input);
			expect(store.get('relais_oidc_return')).toBe(expected);
		});

		it.each([
			['an absolute URL', 'https://evil.example/steal'],
			['a protocol-relative URL', '//evil.example/steal'],
			['a scheme-only target', 'javascript:alert(1)'],
			['a bare host', 'evil.example']
		])('refuses %s and falls back to the root', async (_name, input) => {
			// Without this, /auth/login?return=https://evil.example is an open redirect
			// that borrows this application's credibility to land someone elsewhere.
			const { cookies, store } = fakeCookies();
			await beginLogin(cookies as never, input);
			expect(store.get('relais_oidc_return')).toBe('/');
		});
	});
});

describe('completeLogin', () => {
	// Every case below is refused before any network call, which is what makes them
	// testable without a provider: the checks that matter happen first.

	async function attempt(
		query: string,
		stored: Record<string, string> = {}
	): Promise<{ error: unknown; store: Map<string, string> }> {
		const { cookies, store } = fakeCookies(stored);
		const url = new URL(`https://mail-admin.example.com/auth/callback${query}`);
		try {
			await completeLogin(cookies as never, url);
			return { error: undefined, store };
		} catch (error) {
			return { error, store };
		}
	}

	it('refuses a callback whose state does not match the stored one', async () => {
		// The check that stops an attacker having a victim's browser finish a login the
		// attacker started.
		const { error } = await attempt('?code=abc&state=attacker', {
			relais_oidc_state: 'browser',
			relais_oidc_verifier: 'verifier'
		});
		expect(error).toBeInstanceOf(LoginError);
		expect((error as Error).message).toMatch(/state does not match/);
	});

	it('refuses a callback with no stored handshake', async () => {
		const { error } = await attempt('?code=abc&state=whatever');
		expect(error).toBeInstanceOf(LoginError);
		expect((error as Error).message).toMatch(/expired/);
	});

	it('refuses a callback missing its code', async () => {
		const { error } = await attempt('?state=browser', {
			relais_oidc_state: 'browser',
			relais_oidc_verifier: 'verifier'
		});
		expect(error).toBeInstanceOf(LoginError);
		expect((error as Error).message).toMatch(/missing its code or state/);
	});

	it("reports the provider's own refusal as the provider's", async () => {
		const { error } = await attempt('?error=access_denied&error_description=nope', {
			relais_oidc_state: 'browser',
			relais_oidc_verifier: 'verifier'
		});
		expect(error).toBeInstanceOf(LoginError);
		expect((error as Error).message).toMatch(/identity provider refused/);
		expect((error as InstanceType<typeof LoginError>).detail).toBe('nope');
	});

	it('clears the handshake cookies whichever way it ends', async () => {
		// A stale state cookie left behind turns the next attempt into a mismatch,
		// which reads as a security warning for what is really leftover state.
		const { store } = await attempt('?code=abc&state=attacker', {
			relais_oidc_state: 'browser',
			relais_oidc_verifier: 'verifier',
			relais_oidc_return: '/backends'
		});
		expect(store.has('relais_oidc_state')).toBe(false);
		expect(store.has('relais_oidc_verifier')).toBe(false);
		expect(store.has('relais_oidc_return')).toBe(false);
	});
});
