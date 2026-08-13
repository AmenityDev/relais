import adapter from '@sveltejs/adapter-node';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		// adapter-node, not a static SPA: this application is a backend-for-frontend
		// (F2). Every call to relais is made from the server, so the browser never
		// holds a token and there is no CORS to configure.
		adapter: adapter(),
		csrf: {
			// No cross-origin form submission is trusted. This is the default, stated
			// explicitly: every write in this app is a same-origin form action, and
			// there is no third party that should ever be able to post to it.
			trustedOrigins: []
		}
	}
};

export default config;
