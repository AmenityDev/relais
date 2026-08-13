<script lang="ts">
	let {
		title,
		hint,
		children
	}: { title: string; hint?: string; children?: import('svelte').Snippet } = $props();
</script>

<div class="rounded-lg border border-dashed border-slate-300 bg-white p-8 text-center">
	<p class="text-sm font-medium text-slate-900">{title}</p>
	{#if hint}<p class="mx-auto mt-1 max-w-prose text-sm text-slate-500">{hint}</p>{/if}
	{#if children}<div class="mt-4">{@render children()}</div>{/if}
</div>
