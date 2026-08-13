<script lang="ts">
	import { page } from '$app/state';
	import { resolve } from '$app/paths';
</script>

<svelte:head><title>relais — error</title></svelte:head>

<div class="mx-auto max-w-lg rounded-lg border border-slate-200 bg-white p-6">
	<p class="text-sm font-medium text-slate-500">{page.status}</p>
	<h1 class="mt-1 text-lg font-semibold">{page.error?.message ?? 'Something went wrong'}</h1>

	{#if page.status === 503}
		<p class="mt-2 text-sm text-slate-600">
			The relais admin API could not be reached. Mail delivery is unaffected by this page being
			unavailable — the workers do not depend on it.
		</p>
	{:else if page.status === 403}
		<p class="mt-2 text-sm text-slate-600">Your account does not have permission for that.</p>
	{/if}

	{#if page.error?.requestId}
		<p class="mt-4 text-xs text-slate-500">
			Request <code class="font-mono">{page.error.requestId}</code>
		</p>
	{/if}

	<a
		href={resolve('/')}
		class="mt-6 inline-flex text-sm font-medium text-brand-700 hover:underline"
	>
		Back to the dashboard
	</a>
</div>
