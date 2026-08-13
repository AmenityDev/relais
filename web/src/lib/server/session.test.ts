import { beforeEach, describe, expect, it, vi } from 'vitest';

// $env/dynamic/private is a virtual module, so it is replaced with a plain object
// the tests can rewrite between cases. vi.hoisted, because vi.mock is lifted above
// the imports and would otherwise close over an undefined binding.
const { testEnv } = vi.hoisted(() => ({ testEnv: {} as Record<string, string | undefined> }));
vi.mock('$env/dynamic/private', () => ({ env: testEnv }));

const { config, resetConfigForTests } = await import('./config');
const { SESSION_COOKIE, cookieSize, decodeSession, encodeSession, needsRefresh, setSession } =
	await import('./session');

const KEY_A = Buffer.alloc(32, 1).toString('base64');
const KEY_B = Buffer.alloc(32, 2).toString('base64');

function useKey(key: string): void {
	for (const name of Object.keys(testEnv)) delete testEnv[name];
	Object.assign(testEnv, {
		RELAIS_WEB_API_URL: 'http://relais:8081',
		RELAIS_WEB_ORIGIN: 'https://mail-admin.example.com',
		RELAIS_WEB_OIDC_ISSUER: 'https://auth.example.com/realms/relais',
		RELAIS_WEB_OIDC_CLIENT_ID: 'client',
		RELAIS_WEB_OIDC_CLIENT_SECRET: 'secret',
		RELAIS_WEB_SESSION_KEY: key
	});
	resetConfigForTests();
}

/**
 * Inverts one byte in place.
 *
 * A helper rather than `bytes[i] ^= 0xff` because noUncheckedIndexedAccess is
 * correct that an index access may be undefined, and silencing it with `!` in a
 * test would be the one place the compiler is told to stop checking.
 */
function flipByte(bytes: Buffer, index: number): void {
	const current = bytes.at(index);
	if (current === undefined) throw new Error(`no byte at ${index}`);
	bytes.writeUInt8(current ^ 0xff, index);
}

const session = {
	accessToken: 'header.payload.signature',
	refreshToken: 'refresh-token-value',
	expiresAt: 1_800_000_000,
	subject: 'user-subject',
	groups: ['relais-admin']
};

beforeEach(() => useKey(KEY_A));

describe('the encrypted session cookie', () => {
	it('round-trips every field', async () => {
		const decoded = await decodeSession(await encodeSession(session));
		expect(decoded).toEqual(session);
	});

	it('produces a different ciphertext each time', async () => {
		// A fresh nonce per write. Without one, two sessions with the same contents
		// would be byte-identical, which leaks equality to anyone watching cookies.
		const first = await encodeSession(session);
		const second = await encodeSession(session);
		expect(first).not.toEqual(second);
		expect(await decodeSession(second)).toEqual(session);
	});

	it('rejects a cookie encrypted with another key', async () => {
		const value = await encodeSession(session);
		useKey(KEY_B);
		expect(await decodeSession(value)).toBeUndefined();
	});

	it('rejects a tampered ciphertext', async () => {
		// This is what the AEAD buys over a plain signature-less encryption: flipping
		// a byte must fail authentication rather than decrypt to something else.
		const value = await encodeSession(session);
		const bytes = Buffer.from(value, 'base64url');
		flipByte(bytes, bytes.length - 1);
		expect(await decodeSession(bytes.toString('base64url'))).toBeUndefined();
	});

	it('rejects a tampered nonce', async () => {
		const value = await encodeSession(session);
		const bytes = Buffer.from(value, 'base64url');
		flipByte(bytes, 0);
		expect(await decodeSession(bytes.toString('base64url'))).toBeUndefined();
	});

	it.each([
		['empty', ''],
		['not base64url', '!!!!'],
		['too short to hold a nonce and a tag', Buffer.alloc(20, 7).toString('base64url')],
		['random bytes of a plausible length', Buffer.alloc(200, 9).toString('base64url')]
	])('rejects a cookie that is %s', async (_name, value) => {
		expect(await decodeSession(value)).toBeUndefined();
	});

	it('rejects a validly encrypted cookie whose payload is the wrong shape', async () => {
		// Someone with the key could still write nonsense — a rotated deployment
		// reusing a key, or a future version changing the schema. Decrypting is not
		// the same as trusting.
		const key = await crypto.subtle.importKey('raw', config().sessionKey, 'AES-GCM', false, [
			'encrypt'
		]);
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const payload = new TextEncoder().encode(JSON.stringify({ a: 123, r: null }));
		const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, payload);
		const combined = Buffer.concat([Buffer.from(nonce), Buffer.from(ciphertext)]);

		expect(await decodeSession(combined.toString('base64url'))).toBeUndefined();
	});

	it('rejects a payload with an empty access token', async () => {
		const empty = { ...session, accessToken: '' };
		expect(await decodeSession(await encodeSession(empty))).toBeUndefined();
	});
});

describe('the cookie size guard rail', () => {
	function fakeCookies() {
		const written: { name: string; value: string }[] = [];
		return {
			written,
			cookies: {
				set: (name: string, value: string) => written.push({ name, value }),
				get: () => undefined,
				delete: () => undefined,
				getAll: () => [],
				serialize: () => ''
			}
		};
	}

	it('counts the name and the attributes, not just the value', () => {
		// Browsers apply the 4096-byte limit to the whole Set-Cookie pair. Measuring
		// the value alone would overstate the headroom by about 60 bytes and let a
		// cookie through that the browser then silently discards.
		const size = cookieSize('relais_session', 'x'.repeat(100));
		expect(size).toBeGreaterThan(100 + 'relais_session'.length);
		expect(size).toBe(
			'relais_session='.length + 100 + '; Path=/; HttpOnly; Secure; SameSite=Lax'.length
		);
	});

	it('writes a normal session without complaint', async () => {
		const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
		const { cookies, written } = fakeCookies();

		await setSession(cookies as never, session);

		expect(written).toHaveLength(1);
		expect(written[0]?.name).toBe(SESSION_COOKIE);
		expect(warn).not.toHaveBeenCalled();
		warn.mockRestore();
	});

	it('warns before the limit rather than after', async () => {
		const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
		const { cookies } = fakeCookies();

		// Sized so the encrypted cookie lands between the warning threshold and the
		// hard limit: the band that exists so drift is visible before it breaks.
		await setSession(cookies as never, { ...session, accessToken: 'a'.repeat(2500) });

		expect(warn).toHaveBeenCalledOnce();
		const logged = JSON.parse(String(warn.mock.calls[0]?.[0])) as Record<string, unknown>;
		expect(logged.msg).toContain('approaching');
		expect(logged.bytes).toBeGreaterThan(3500);
		warn.mockRestore();
	});

	it('refuses to write a cookie the browser would drop', async () => {
		const { cookies, written } = fakeCookies();

		// A silently discarded cookie shows up as an endless login loop with nothing
		// in the logs. Failing loudly is the whole point.
		await expect(
			setSession(cookies as never, { ...session, accessToken: 'a'.repeat(6000) })
		).rejects.toThrow(/over the 4096-byte limit/);
		expect(written).toHaveLength(0);
	});

	it('sets httpOnly, secure and lax on the cookie it writes', async () => {
		const options: Record<string, unknown>[] = [];
		const cookies = {
			set: (_name: string, _value: string, opts: Record<string, unknown>) => options.push(opts)
		};

		await setSession(cookies as never, session);

		expect(options[0]).toMatchObject({ httpOnly: true, secure: true, sameSite: 'lax', path: '/' });
	});

	it('drops Secure only when configuration asked for it', async () => {
		useKey(KEY_A);
		testEnv.RELAIS_WEB_ORIGIN = 'http://localhost:3000';
		testEnv.RELAIS_WEB_INSECURE_COOKIE = 'true';
		resetConfigForTests();

		const options: Record<string, unknown>[] = [];
		const cookies = {
			set: (_name: string, _value: string, opts: Record<string, unknown>) => options.push(opts)
		};
		await setSession(cookies as never, session);

		expect(options[0]).toMatchObject({ secure: false, httpOnly: true });
	});
});

describe('needsRefresh', () => {
	it('renews before expiry, not at it', () => {
		// Renewing exactly at expiry means every request in the last second of a token
		// races the API's own clock.
		expect(needsRefresh({ ...session, expiresAt: 1000 } as never, 900, 60)).toBe(false);
		expect(needsRefresh({ ...session, expiresAt: 1000 } as never, 940, 60)).toBe(true);
		expect(needsRefresh({ ...session, expiresAt: 1000 } as never, 1200, 60)).toBe(true);
	});
});
