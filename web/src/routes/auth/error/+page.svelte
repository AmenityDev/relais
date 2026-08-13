<script lang="ts">
	import { resolve } from '$app/paths';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();
</script>

<svelte:head><title>relais — signed out</title></svelte:head>

<main class="grid min-h-full place-items-center p-6">
	<div class="w-full max-w-md rounded-lg border border-slate-200 bg-white p-6 shadow-sm">
		<h1 class="text-lg font-semibold">Not signed in</h1>
		<p class="mt-2 text-sm text-slate-600">{data.reason}</p>
		<a
			href={resolve('/auth/login')}
			class="mt-6 inline-flex rounded-md bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700"
		>
			Sign in
		</a>
	</div>
</main>
