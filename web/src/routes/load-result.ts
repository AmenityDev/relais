/**
 * Narrows a load function's result for a test.
 *
 * SvelteKit types a load as returning `void | Data`, because a load may redirect or
 * throw instead of returning. A test that has already asserted the happy path knows
 * it got data; this states that in one place rather than casting at every call site,
 * and fails loudly if the assumption is ever wrong.
 */
export function loaded<T>(result: T | void): T {
	if (result === undefined || result === null) {
		throw new Error('the load function returned nothing');
	}
	return result;
}
