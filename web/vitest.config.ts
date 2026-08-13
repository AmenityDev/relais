import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vitest/config';

// The SvelteKit plugin is loaded so that $lib and $env resolve exactly as they do
// at runtime. Without it, a test would have to mock the module graph and could pass
// against a shape the real build never sees.
export default defineConfig({
	plugins: [sveltekit()],
	test: {
		// The server layer is Node code: no DOM, and no jsdom to install.
		environment: 'node',
		include: ['src/**/*.test.ts']
	}
});
