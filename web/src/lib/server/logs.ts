import { config } from './config';

// Deep links into the log store (F8). Logs live in ClickStack/HyperDX, not in
// Postgres, so the interface does not show log lines: it hands over the search that
// finds them.
//
// Every builder returns undefined when no template is configured, so a deployment
// without a log store renders no link rather than a dead one.

/** Escapes and substitutes the search terms into the configured template. */
function build(query: string): string | undefined {
	const template = config().logsUrlTemplate;
	if (template === '') return undefined;
	return template.replace('{query}', encodeURIComponent(query));
}

/**
 * The lines for one message.
 *
 * Searched by id rather than by recipient or subject: the id is in every log line
 * the pipeline writes, and neither address nor subject is ever logged.
 */
export function messageLogsUrl(messageId: string): string | undefined {
	return build(`message_id:"${messageId}"`);
}

/** The lines for one request, which is what a support conversation starts from. */
export function requestLogsUrl(requestId: string): string | undefined {
	return build(`request_id:"${requestId}"`);
}

/**
 * Everything one credential did.
 *
 * This is the query that matters when a credential is suspected of being
 * compromised: every rejection relais recorded, with enough context to investigate,
 * and no message content.
 */
export function credentialLogsUrl(credentialId: string): string | undefined {
	return build(`credential_id:"${credentialId}"`);
}
