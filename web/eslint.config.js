import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import svelte from 'eslint-plugin-svelte';
import globals from 'globals';
import ts from 'typescript-eslint';
import svelteConfig from './svelte.config.js';

export default ts.config(
	js.configs.recommended,
	...ts.configs.recommended,
	...svelte.configs.recommended,
	prettier,
	...svelte.configs.prettier,
	{
		languageOptions: {
			globals: { ...globals.browser, ...globals.node }
		},
		rules: {
			// A leading underscore marks a binding that exists only to be discarded —
			// destructuring a secret out of an object before it is echoed back, for
			// instance. Without this the alternative is a delete, which is worse.
			'@typescript-eslint/no-unused-vars': [
				'error',
				{
					argsIgnorePattern: '^_',
					varsIgnorePattern: '^_',
					caughtErrorsIgnorePattern: '^_',
					ignoreRestSiblings: true
				}
			]
		}
	},
	{
		files: ['**/*.svelte', '**/*.svelte.ts', '**/*.svelte.js'],
		languageOptions: {
			parserOptions: {
				projectService: true,
				extraFileExtensions: ['.svelte'],
				parser: ts.parser,
				svelteConfig
			}
		}
	},
	{
		// A generic pager cannot contain a literal route id — that is what makes it
		// generic. The caller passes an already-resolved path, so the link still goes
		// through resolve(); the rule simply cannot see through the prop. Scoped to
		// this one file rather than disabled globally, so every other link is still
		// checked.
		files: ['src/lib/components/Pagination.svelte'],
		rules: { 'svelte/no-navigation-without-resolve': 'off' }
	},
	{
		// Generated: the shape is the OpenAPI document's, not ours to lint.
		ignores: ['.svelte-kit/', 'build/', 'src/lib/api.generated.d.ts']
	}
);
