import { describe, expect, it } from 'vitest';
import type { Credential } from './api';
import { filterCredentials, parseFilter } from './credential-filter';

function credential(overrides: Partial<Credential>): Credential {
	return {
		id: 'id',
		name: 'app',
		type: 'api_key',
		lookup: 'rk_abc',
		state: 'active',
		enabled: true,
		rate_limit_rps: null,
		rate_limit_burst: null,
		pattern_count: 1,
		recipient_pattern_count: 1,
		created_by: 'admin',
		created_at: '2026-01-01T00:00:00Z',
		last_used_at: null,
		revoked_at: null,
		...overrides
	};
}

const rows = [
	credential({ id: '1', name: 'WordPress', type: 'smtp_user', lookup: 'blog' }),
	credential({ id: '2', name: 'billing', lookup: 'rk_9f3a', state: 'revoked', pattern_count: 0 }),
	credential({ id: '3', name: 'alerts', state: 'disabled', recipient_pattern_count: 0 })
];

const ids = (filter: string) =>
	filterCredentials(rows, parseFilter(new URLSearchParams(filter))).map((c) => c.id);

describe('filtering credentials', () => {
	it('returns every row without a filter', () => {
		expect(ids('')).toEqual(['1', '2', '3']);
	});

	it('searches the name and the username, ignoring case', () => {
		expect(ids('q=wordp')).toEqual(['1']);
		expect(ids('q=BLOG')).toEqual(['1']);
	});

	it('searches an api_key by its prefix too', () => {
		expect(ids('q=rk_9f')).toEqual(['2']);
	});

	it('combines filters', () => {
		expect(ids('type=api_key&state=disabled')).toEqual(['3']);
		expect(ids('q=blog&type=api_key')).toEqual([]);
	});

	it('finds the risky end of each allow-list', () => {
		expect(ids('allow_list=no_sender')).toEqual(['2']);
		expect(ids('allow_list=any_recipient')).toEqual(['3']);
	});

	it('ignores a value it does not know rather than matching nothing', () => {
		// A stale link narrowing to an empty list would read as "there are none".
		expect(ids('state=deleted&type=oauth')).toEqual(['1', '2', '3']);
	});
});
