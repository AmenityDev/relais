<script lang="ts">
	import { resolve } from '$app/paths';
	import Badge from '$lib/components/Badge.svelte';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();
	const m = $derived(data.message);
</script>

<svelte:head><title>relais — message</title></svelte:head>

<a href={resolve('/messages')} class="text-sm font-medium text-brand-700 hover:underline"
	>← Messages</a
>
<h1 class="mt-2 flex flex-wrap items-center gap-2 text-xl font-semibold">
	Message
	<Badge tone={m.status === 'sent' ? 'good' : m.status === 'queued' ? 'info' : 'bad'}>
		{m.status}
	</Badge>
</h1>

{#if m.error}
	<div class="mt-4 rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-900">
		<p class="font-medium">{m.error.code}</p>
		<!-- The relay's own words, kept verbatim: paraphrasing an SMTP reply loses the
		     detail that identifies the cause. -->
		<p class="mt-1 font-mono text-xs break-all">{m.error.detail}</p>
	</div>
{/if}

{#if m.rejection_reason}
	<div class="mt-4 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
		relais refused this message: <strong>{m.rejection_reason}</strong>
	</div>
{/if}

{#if data.logsUrl}
	<!-- Content is not stored past delivery and no endpoint returns it, so the log
	     store is where the detail lives. This hands over the search rather than
	     pretending to show lines relais does not keep. -->
	<p class="mt-4 text-sm">
		<!-- An external URL, to whatever log store is configured. resolve() is for
		     internal pathnames; putting one through it would rewrite a foreign origin. -->
		<!-- eslint-disable-next-line svelte/no-navigation-without-resolve -->
		<a href={data.logsUrl} rel="noreferrer" class="font-medium text-brand-700 hover:underline">
			Open this message's log lines →
		</a>
	</p>
{/if}

<dl
	class="mt-6 grid gap-x-6 gap-y-3 rounded-lg border border-slate-200 bg-white p-4 sm:grid-cols-2"
>
	{#each [['From', m.from], ['To', m.to.join(', ')], ['Cc', m.cc?.join(', ') ?? '—'], ['Bcc', m.bcc?.join(', ') ?? '—'], ['Subject', m.subject], ['Envelope recipients', m.recipients.join(', ')], ['Message-ID', m.message_id], ['Credential', m.credential_name ?? '—'], ['Relay', m.backend_name ?? '—'], ['Façade', m.facade], ['Size', `${m.size_bytes} bytes`], ['Attempts', String(m.attempts)], ['Submitted from', m.remote_ip ?? '—'], ['Created', m.created_at], ['Sent', m.sent_at ?? '—']] as [label, value] (label)}
		<div>
			<dt class="text-xs font-medium tracking-wide text-slate-500 uppercase">{label}</dt>
			<dd class="mt-0.5 font-mono text-sm break-all">{value}</dd>
		</div>
	{/each}
</dl>
