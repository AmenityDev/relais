import type { Session } from '$lib/server/session';

// The ambient types for this app. `locals` is server-only state, populated by
// hooks.server.ts and read by load functions.
declare global {
	namespace App {
		interface Locals {
			/** The decrypted session, or undefined when not signed in. */
			session?: Session;
			/** Correlates a request's log lines with the Go side's. */
			requestId: string;
		}

		interface PageData {
			/** Present on every page through the root layout. */
			identity?: {
				subject: string;
				email?: string;
				name?: string;
				role: string;
				can_write: boolean;
				groups: string[];
			};
		}

		interface Error {
			code?: string;
			requestId?: string;
		}
	}
}

export {};
