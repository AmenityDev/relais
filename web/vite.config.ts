import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],
	server: {
		// The dev server is for one developer on one machine. Binding it to every
		// interface would put an authenticated admin session on the local network.
		host: '127.0.0.1',
		port: 5173
	}
});
