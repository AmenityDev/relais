import { error } from '@sveltejs/kit';
import type { components, paths } from '$lib/api.generated';
import { config } from './config';

// The only place that talks to the Go admin API.
//
// It is server-only, which is what F2 is about: the browser never holds a token,
// so it also never calls relais. That means no CORS, no token in JavaScript reach,
// and one place where an authorization header is attached.

/** Shorthand for the generated schemas, so screens do not import paths themselves. */
export type Schemas = components['schemas'];
export type Identity = Schemas['Identity'];
export type Backend = Schemas['Backend'];
export type Domain = Schemas['Domain'];
export type Credential = Schemas['Credential'];
export type CreatedCredential = Schemas['CreatedCredential'];
export type Pattern = Schemas['Pattern'];
export type Message = Schemas['Message'];
export type Stats = Schemas['Stats'];
export type ProbeResult = Schemas['ProbeResult'];
export type PatternValidation = Schemas['PatternValidation'];
export type PatternTest = Schemas['PatternTest'];
export type ResolveResult = Schemas['ResolveResult'];
export type ApiError = Schemas['Error'];
export type ApiErrorDetail = Schemas['ErrorDetail'];

/** Every path the admin API serves, from the generated document. */
export type ApiPath = keyof paths;

export interface RequestOptions {
	method?: 'GET' | 'POST' | 'PATCH' | 'DELETE';
	/** JSON body. Serialised here so no caller forgets the content type. */
	body?: unknown;
	query?: Record<string, string | number | undefined>;
	/** Correlates this call with the request that caused it. */
	requestId?: string;
	signal?: AbortSignal;
}

/** A failed call, carrying the API's own error code so a caller can branch on it. */
export class ApiCallError extends Error {
	constructor(
		readonly status: number,
		readonly code: string,
		message: string,
		readonly field?: string
	) {
		super(message);
		this.name = 'ApiCallError';
	}
}

/**
 * Calls the admin API with the session's access token.
 *
 * The token is passed in rather than read from a module-level store, so there is
 * no ambient "current user" that a background task could accidentally inherit.
 */
export async function apiFetch<T>(
	accessToken: string,
	path: string,
	options: RequestOptions = {}
): Promise<T> {
	const { apiBaseUrl } = config();
	const url = new URL(apiBaseUrl + path);

	for (const [key, value] of Object.entries(options.query ?? {})) {
		if (value !== undefined && value !== '') url.searchParams.set(key, String(value));
	}

	const headers: Record<string, string> = {
		Authorization: `Bearer ${accessToken}`,
		Accept: 'application/json'
	};
	if (options.requestId !== undefined) headers['X-Request-Id'] = options.requestId;

	let body: string | undefined;
	if (options.body !== undefined) {
		body = JSON.stringify(options.body);
		headers['Content-Type'] = 'application/json';
	}

	let response: Response;
	try {
		response = await fetch(url, {
			method: options.method ?? 'GET',
			headers,
			...(body === undefined ? {} : { body }),
			...(options.signal === undefined ? {} : { signal: options.signal })
		});
	} catch {
		// The API being unreachable is an operational failure, not the caller's
		// mistake, and it must not read as "you are signed out". The underlying
		// network error is not surfaced: it would name internal hosts.
		throw new ApiCallError(
			503,
			'api_unreachable',
			`the relais admin API at ${apiBaseUrl} could not be reached`,
			undefined
		);
	}

	if (response.status === 204) return undefined as T;

	const text = await response.text();
	if (!response.ok) {
		throw toApiError(response.status, text);
	}

	if (text === '') return undefined as T;
	try {
		return JSON.parse(text) as T;
	} catch {
		throw new ApiCallError(
			502,
			'invalid_response',
			'the admin API returned a body that is not JSON'
		);
	}
}

function toApiError(status: number, text: string): ApiCallError {
	let code = 'unknown';
	let message = `the admin API returned ${status}`;
	let field: string | undefined;

	try {
		// The API wraps every error as {"error": {...}}. Reading the fields off the
		// envelope found nothing, so an operator saw "the admin API returned 422" where
		// the server had said "backend auth password was given without a user".
		const parsed = JSON.parse(text) as Partial<ApiError>;
		const detail = (parsed.error ?? {}) as Partial<ApiErrorDetail>;
		if (typeof detail.code === 'string' && detail.code !== '') code = detail.code;
		if (typeof detail.message === 'string' && detail.message !== '') message = detail.message;
		if (typeof detail.field === 'string' && detail.field !== '') field = detail.field;
	} catch {
		// A non-JSON error body is itself information: keep the default message
		// rather than exposing whatever HTML a proxy returned.
	}

	return new ApiCallError(status, code, message, field);
}

/**
 * Turns an API failure into a SvelteKit error, mapping the statuses that mean
 * something specific to a person looking at a screen.
 *
 * 401 is deliberately not mapped to a redirect here: by the time a load function
 * runs, hooks.server.ts has already refreshed or cleared the session, so a 401
 * from the API means the token was rejected for a reason a refresh will not fix.
 */
export function failWith(cause: unknown): never {
	if (cause instanceof ApiCallError) {
		if (cause.status === 503 || cause.code === 'api_unreachable') {
			error(503, { message: cause.message, code: cause.code });
		}
		error(cause.status, { message: cause.message, code: cause.code });
	}
	throw cause;
}
