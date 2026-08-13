import { error } from '@sveltejs/kit';
import type { Identity } from './api';

// Go is the authority on what a role may do (F6). Nothing here decides anything:
// it reads the identity the API reported and reflects it in the interface.
//
// The distinction matters because it decides where a bug can hurt. A wrong answer
// here renders a button that should not be there, and the API refuses it with 403.
// A wrong answer in Go lets a viewer change something. So this file is allowed to
// be a convenience, and is never allowed to be the check.

export function canWrite(identity: Identity | undefined): boolean {
	return identity?.can_write === true;
}

/**
 * Refuses a write for a viewer, before a form action calls the API.
 *
 * This is not the security boundary — the API's is — but it turns "the button did
 * nothing" into a message that says why, and it keeps a viewer's mistaken click
 * out of the audit log as a 403.
 */
export function requireWrite(identity: Identity | undefined): void {
	if (!canWrite(identity)) {
		error(403, {
			message: 'Your account has read-only access to relais.',
			code: 'read_only'
		});
	}
}

/** A short label for the current role, for the header. */
export function roleLabel(identity: Identity | undefined): string {
	if (identity === undefined) return 'signed out';
	return identity.can_write ? identity.role : `${identity.role} (read-only)`;
}
