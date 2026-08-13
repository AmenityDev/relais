import type { PageServerLoad } from './$types';

export const load: PageServerLoad = ({ url }) => {
	return {
		// Echoed back as text only, never as markup. It comes from a query parameter
		// and Svelte escapes it, but it is worth stating why it is safe to show.
		reason: url.searchParams.get('reason') ?? 'You are signed out.'
	};
};
