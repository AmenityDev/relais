<script lang="ts">
	import '../app.css';
	import { page } from '$app/state';
	import { resolve } from '$app/paths';
	import type { LayoutData } from './$types';

	let { data, children }: { data: LayoutData; children: import('svelte').Snippet } = $props();

	// resolve() rather than a bare string: it applies the base path and, more
	// usefully, type-checks the route against the ones that exist. A renamed
	// directory becomes a build error instead of a dead link.
	const nav = [
		{ href: resolve('/'), label: 'Dashboard' },
		{ href: resolve('/backends'), label: 'Relays' },
		{ href: resolve('/domains'), label: 'Domains' },
		{ href: resolve('/credentials'), label: 'Credentials' },
		{ href: resolve('/messages'), label: 'Messages' }
	];

	function isCurrent(href: string): boolean {
		if (href === resolve('/')) return page.url.pathname === href;
		return page.url.pathname === href || page.url.pathname.startsWith(href + '/');
	}
</script>

<div class="flex min-h-full flex-col">
	<header class="border-b border-slate-200 bg-white">
		<div class="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
			<a href={resolve('/')} class="text-base font-semibold tracking-tight">relais</a>

			<nav aria-label="Sections" class="flex flex-wrap gap-1">
				{#each nav as item (item.href)}
					<a
						href={item.href}
						aria-current={isCurrent(item.href) ? 'page' : undefined}
						class="rounded-md px-3 py-1.5 text-sm font-medium {isCurrent(item.href)
							? 'bg-brand-50 text-brand-700'
							: 'text-slate-600 hover:bg-slate-100'}"
					>
						{item.label}
					</a>
				{/each}
			</nav>

			<div class="ml-auto flex items-center gap-3 text-sm">
				{#if data.identity}
					<span class="text-slate-600">
						{data.identity.email || data.identity.name || data.identity.subject}
						{#if !data.identity.can_write}
							<span class="ml-1 text-xs text-slate-500">(read-only)</span>
						{/if}
					</span>
					<!-- A form, not a link: a sign-out that any page could trigger by
					     embedding an image or a prefetch is a nuisance at best. -->
					<form method="POST" action={resolve('/auth/logout')}>
						<button
							type="submit"
							class="rounded-md border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50"
						>
							Sign out
						</button>
					</form>
				{/if}
			</div>
		</div>
	</header>

	<main class="mx-auto w-full max-w-7xl flex-1 px-4 py-6">
		{@render children()}
	</main>
</div>
