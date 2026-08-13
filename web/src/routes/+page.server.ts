import { apiFetch, failWith, type Message, type Stats } from '$lib/server/api';
import { requireSession } from '$lib/server/session';
import type { PageServerLoad } from './$types';

interface MessageList {
	data: Message[];
	next_cursor?: string;
}

export const load: PageServerLoad = async ({ locals }) => {
	const token = requireSession(locals).accessToken;
	const requestId = locals.requestId;

	try {
		// Both at once: the dashboard is the first page anyone opens, and two
		// sequential round trips to the API would be visible.
		const [stats, rejected] = await Promise.all([
			apiFetch<Stats>(token, '/admin/v1/stats', { requestId }),
			apiFetch<MessageList>(token, '/admin/v1/messages', {
				requestId,
				query: { status: 'rejected', limit: 8 }
			})
		]);
		return { stats, rejected: rejected.data };
	} catch (cause) {
		failWith(cause);
	}
};
