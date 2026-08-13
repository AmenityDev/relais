import { apiFetch, failWith, type Message } from '$lib/server/api';
import { requireSession } from '$lib/server/session';
import type { PageServerLoad } from './$types';

const STATUSES = ['queued', 'sending', 'sent', 'failed', 'rejected', 'partial'] as const;

export const load: PageServerLoad = async ({ locals, url }) => {
	const status = url.searchParams.get('status') ?? '';
	const cursor = url.searchParams.get('cursor') ?? '';

	try {
		const list = await apiFetch<{ data: Message[]; next_cursor?: string }>(
			requireSession(locals).accessToken,
			'/admin/v1/messages',
			{
				requestId: locals.requestId,
				query: {
					// Only a known status is forwarded. An arbitrary one would come back as a
					// 422 rendered as an error page, when the honest answer to a bad filter in
					// a URL is to ignore it.
					...((STATUSES as readonly string[]).includes(status) ? { status } : {}),
					...(cursor === '' ? {} : { cursor })
				}
			}
		);
		return {
			messages: list.data,
			nextCursor: list.next_cursor,
			status,
			statuses: STATUSES
		};
	} catch (cause) {
		failWith(cause);
	}
};
