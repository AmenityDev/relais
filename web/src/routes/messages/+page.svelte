<script lang="ts">
	import { resolve } from '$app/paths';
	import Badge from '$lib/components/Badge.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import Table from '$lib/components/Table.svelte';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();

	const tone = (status: string) =>
		status === 'sent'
			? 'good'
			: status === 'failed' || status === 'rejected'
				? 'bad'
				: status === 'partial'
					? 'warn'
					: 'info';
</script>

<svelte:head><title>relais — messages</title></svelte:head>

<h1 class="text-xl font-semibold">Messages</h1>
<p class="mt-1 max-w-prose text-sm text-slate-500">
	What was submitted and what became of it. Message content is not stored beyond delivery and is
	returned by no endpoint, so it is not shown here.
</p>

<nav class="mt-4 flex flex-wrap gap-1" aria-label="Filter by status">
	<a
		href={resolve('/messages')}
		aria-current={data.status === '' ? 'page' : undefined}
		class="rounded-md px-3 py-1.5 text-sm {data.status === ''
			? 'bg-brand-50 font-medium text-brand-700'
			: 'text-slate-600 hover:bg-slate-100'}"
	>
		All
	</a>
	{#each data.statuses as status (status)}
		<a
			href="{resolve('/messages')}?status={status}"
			aria-current={data.status === status ? 'page' : undefined}
			class="rounded-md px-3 py-1.5 text-sm {data.status === status
				? 'bg-brand-50 font-medium text-brand-700'
				: 'text-slate-600 hover:bg-slate-100'}"
		>
			{status}
		</a>
	{/each}
</nav>

<div class="mt-4">
	{#if data.messages.length === 0}
		<EmptyState
			title="No messages"
			hint={data.status === ''
				? 'Nothing has been submitted yet.'
				: `Nothing with status ${data.status}.`}
		/>
	{:else}
		<Table
			columns={['Status', 'From', 'To', 'Credential', 'When', '']}
			rows={data.messages}
			caption="Submitted messages"
		>
			{#snippet row(message)}
				<tr>
					<td class="px-4 py-2.5">
						<Badge tone={tone(message.status)}>{message.status}</Badge>
						{#if message.attempts > 1}
							<span class="ml-1 text-xs text-slate-500">×{message.attempts}</span>
						{/if}
					</td>
					<td class="px-4 py-2.5 font-mono text-xs">{message.from}</td>
					<td class="px-4 py-2.5 text-xs">{message.to.join(', ')}</td>
					<td class="px-4 py-2.5 text-xs">{message.credential_name ?? '—'}</td>
					<td class="px-4 py-2.5 text-xs text-slate-500">{message.created_at}</td>
					<td class="px-4 py-2.5 text-right">
						<a
							href={resolve('/messages/[id]', { id: message.id })}
							class="text-xs font-medium text-brand-700 hover:underline"
						>
							Detail
						</a>
					</td>
				</tr>
			{/snippet}
		</Table>
		<Pagination
			nextCursor={data.nextCursor}
			path={resolve('/messages')}
			params={data.status === '' ? {} : { status: data.status }}
		/>
	{/if}
</div>
