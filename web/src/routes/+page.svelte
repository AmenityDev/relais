<script lang="ts">
	import { resolve } from '$app/paths';
	import Badge from '$lib/components/Badge.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();

	// The order an operator scans, not alphabetical: what is stuck, then what failed,
	// then what worked.
	const order = ['queued', 'sending', 'failed', 'partial', 'rejected', 'sent'] as const;

	const tone = (status: string) =>
		status === 'sent'
			? 'good'
			: status === 'failed' || status === 'rejected'
				? 'bad'
				: status === 'partial'
					? 'warn'
					: 'info';
</script>

<svelte:head><title>relais — dashboard</title></svelte:head>

<h1 class="text-xl font-semibold">Dashboard</h1>

<div class="mt-4 grid gap-3 sm:grid-cols-3">
	<div class="rounded-lg border border-slate-200 bg-white p-4">
		<p class="text-xs font-medium tracking-wide text-slate-500 uppercase">Relays</p>
		<p class="mt-1 text-2xl font-semibold">{data.stats.backends}</p>
	</div>
	<div class="rounded-lg border border-slate-200 bg-white p-4">
		<p class="text-xs font-medium tracking-wide text-slate-500 uppercase">Domains</p>
		<p class="mt-1 text-2xl font-semibold">{data.stats.domains}</p>
	</div>
	<div class="rounded-lg border border-slate-200 bg-white p-4">
		<p class="text-xs font-medium tracking-wide text-slate-500 uppercase">Credentials</p>
		<p class="mt-1 text-2xl font-semibold">
			{Object.entries(data.stats.credentials)
				.filter(([state]) => state === 'active')
				.map(([, count]) => count)
				.at(0) ?? 0}
			<span class="text-sm font-normal text-slate-500">active</span>
		</p>
	</div>
</div>

<h2 class="mt-8 text-sm font-semibold tracking-wide text-slate-500 uppercase">Messages</h2>
<div class="mt-2 flex flex-wrap gap-2">
	{#each order as status (status)}
		<a
			href="{resolve('/messages')}?status={status}"
			class="rounded-lg border border-slate-200 bg-white px-4 py-2 hover:bg-slate-50"
		>
			<span class="text-sm text-slate-600">{status}</span>
			<span class="ml-2 font-semibold">{data.stats.messages[status] ?? 0}</span>
		</a>
	{/each}
</div>

<h2 class="mt-8 text-sm font-semibold tracking-wide text-slate-500 uppercase">Latest rejections</h2>
<p class="mt-1 text-sm text-slate-500">
	A rejection is relais refusing to send: nearly always an address no pattern allows, or a domain
	nothing routes.
</p>

<div class="mt-3">
	{#if data.rejected.length === 0}
		<EmptyState title="No rejections" hint="Every submission so far was authorised." />
	{:else}
		<ul class="divide-y divide-slate-100 rounded-lg border border-slate-200 bg-white">
			{#each data.rejected as message (message.id)}
				<li class="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3 text-sm">
					<Badge tone={tone(message.status)}>{message.rejection_reason ?? message.status}</Badge>
					<code class="font-mono text-xs">{message.from}</code>
					<span class="text-slate-500">→ {message.to.join(', ')}</span>
					<span class="ml-auto text-xs text-slate-400">{message.created_at}</span>
					<a
						href={resolve('/messages/[id]', { id: message.id })}
						class="text-xs font-medium text-brand-700 hover:underline"
					>
						Detail
					</a>
				</li>
			{/each}
		</ul>
	{/if}
</div>
