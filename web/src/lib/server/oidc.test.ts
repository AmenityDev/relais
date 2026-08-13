import { beforeEach, describe, expect, it, vi } from 'vitest';

const { testEnv } = vi.hoisted(() => ({ testEnv: {} as Record<string, string | undefined> }));
vi.mock('$env/dynamic/private', () => ({ env: testEnv }));

const { resetConfigForTests } = await import('./config');
const { LoginError, beginLogin, completeLogin } = await import('./oidc');

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
		RELAIS_WEB_OIDC_BASE_URL: 'https://auth.example.com',
		RELAIS_WEB_OIDC_CLIENT_ID: 'client-id',
		RELAIS_WEB_OIDC_CLIENT_SECRET: 'client-secret',
		RELAIS_WEB_SESSION_KEY: Buffer.alloc(32, 6).toString('base64')
	});
	resetConfigForTests();
});

describe('beginLogin', () => {
	it('sends the browser to the issuer with PKCE and a state', () => {
		const { cookies, store } = fakeCookies();
		const url = beginLogin(cookies as never, '/backends');

		expect(url.origin).toBe('https://auth.example.com');
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

	it('stores the handshake cookies as httpOnly with a short life', () => {
		const options: Record<string, unknown>[] = [];
		const cookies = {
			set: (_n: string, _v: string, opts: Record<string, unknown>) => options.push(opts),
			get: () => undefined,
			delete: () => undefined
		};

		beginLogin(cookies as never, '/');

		expect(options).toHaveLength(3);
		for (const opts of options) {
			expect(opts).toMatchObject({ httpOnly: true, secure: true, sameSite: 'lax' });
			expect(opts.maxAge).toBe(600);
		}
	});

	it('mints a fresh state and verifier for each attempt', () => {
		const first = fakeCookies();
		const second = fakeCookies();
		beginLogin(first.cookies as never, '/');
		beginLogin(second.cookies as never, '/');

		expect(first.store.get('relais_oidc_state')).not.toBe(second.store.get('relais_oidc_state'));
		expect(first.store.get('relais_oidc_verifier')).not.toBe(
			second.store.get('relais_oidc_verifier')
		);
	});

	describe('the post-login redirect', () => {
		it.each([
			['/messages?status=failed', '/messages?status=failed'],
			['/', '/']
		])('keeps an internal path (%s)', (input, expected) => {
			const { cookies, store } = fakeCookies();
			beginLogin(cookies as never, input);
			expect(store.get('relais_oidc_return')).toBe(expected);
		});

		it.each([
			['an absolute URL', 'https://evil.example/steal'],
			['a protocol-relative URL', '//evil.example/steal'],
			['a scheme-only target', 'javascript:alert(1)'],
			['a bare host', 'evil.example']
		])('refuses %s and falls back to the root', (_name, input) => {
			// Without this, /auth/login?return=https://evil.example is an open redirect
			// that borrows this application's credibility to land someone elsewhere.
			const { cookies, store } = fakeCookies();
			beginLogin(cookies as never, input);
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
