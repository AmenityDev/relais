import type { Credential } from './api';

export const TYPES = ['api_key', 'smtp_user'] as const;
export const STATES = ['active', 'disabled', 'revoked'] as const;
// The two allow-list conditions worth hunting for, each the risky end of its list:
// a credential that can send as nobody, and one that can send to anybody.
export const ALLOW_LISTS = ['no_sender', 'any_recipient'] as const;

export type CredentialFilter = {
	q: string;
	type: string;
	state: string;
	allowList: string;
};

// An unknown value in the URL is dropped rather than matched literally: a stale or
// mistyped link should show everything, not an empty list that looks like a fact.
function known(values: readonly string[], value: string | null): string {
	return value !== null && values.includes(value) ? value : '';
}

export function parseFilter(params: URLSearchParams): CredentialFilter {
	return {
		q: (params.get('q') ?? '').trim(),
		type: known(TYPES, params.get('type')),
		state: known(STATES, params.get('state')),
		allowList: known(ALLOW_LISTS, params.get('allow_list'))
	};
}

// Filtering happens here rather than in the API because the API already returns
// every row (see `truncated` in the credentials page load). The search covers the lookup as well as the
// name: for an smtp_user that is the username, for an api_key the key's prefix,
// which is what an operator has in hand when tracing a client back to its row.
export function filterCredentials(rows: Credential[], filter: CredentialFilter): Credential[] {
	const needle = filter.q.toLowerCase();
	return rows.filter(
		(c) =>
			(needle === '' ||
				c.name.toLowerCase().includes(needle) ||
				c.lookup.toLowerCase().includes(needle)) &&
			(filter.type === '' || c.type === filter.type) &&
			(filter.state === '' || c.state === filter.state) &&
			(filter.allowList === '' ||
				(filter.allowList === 'no_sender' && c.pattern_count === 0) ||
				(filter.allowList === 'any_recipient' && c.recipient_pattern_count === 0))
	);
}
