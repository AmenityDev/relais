import { apiFetch, failWith, type Message } from '$lib/server/api';
import { messageLogsUrl } from '$lib/server/logs';
import { requireSession } from '$lib/server/session';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals, params }) => {
	try {
		const message = await apiFetch<Message>(
			requireSession(locals).accessToken,
			`/admin/v1/messages/${encodeURIComponent(params.id)}`,
			{ requestId: locals.requestId }
		);
		return { message, logsUrl: messageLogsUrl(message.id) };
	} catch (cause) {
		failWith(cause);
	}
};
