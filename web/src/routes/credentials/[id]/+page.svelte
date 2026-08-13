<script lang="ts">
	import { resolve } from '$app/paths';
	import Badge from '$lib/components/Badge.svelte';
	import ConfirmButton from '$lib/components/ConfirmButton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import Field from '$lib/components/Field.svelte';
	import type { ActionData, PageData } from './$types';

	let { data, form }: { data: PageData; form: ActionData } = $props();

	const validation = $derived(form && 'validation' in form ? form.validation : undefined);
	const test = $derived(form && 'test' in form ? form.test : undefined);
	const values = $derived((form && 'values' in form ? form.values : {}) as Record<string, string>);
</script>

<svelte:head><title>relais — {data.credential.name}</title></svelte:head>

<a href={resolve('/credentials')} class="text-sm font-medium text-brand-700 hover:underline"
	>← Credentials</a
>
<h1 class="mt-2 flex flex-wrap items-center gap-2 text-xl font-semibold">
	{data.credential.name}
	<Badge tone={data.credential.state === 'active' ? 'good' : 'bad'}>{data.credential.state}</Badge>
	<Badge>{data.credential.type}</Badge>
</h1>

{#if form && 'message' in form && form.message}
	<p
		class="mt-4 rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-800"
		role="alert"
	>
		{form.message}
	</p>
{/if}

<h2 class="mt-8 text-sm font-semibold tracking-wide text-slate-500 uppercase">Allowed senders</h2>

<div class="mt-3">
	{#if data.patterns.length === 0}
		<EmptyState
			title="This credential can send as nobody"
			hint="Every submission it makes will be rejected until an allowed sender is added."
		/>
	{:else}
		<ul class="divide-y divide-slate-100 rounded-lg border border-slate-200 bg-white">
			{#each data.patterns as pattern (pattern.id)}
				<li class="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3">
					<code class="font-mono text-sm">{pattern.pattern}</code>
					<!-- The explanation comes from Go, which renders the grammar in words. The
					     surprising case (*@*.example.com not covering example.com) is exactly
					     what an operator needs told rather than left to infer. -->
					<span class="text-xs text-slate-500">{pattern.explanation}</span>
					{#if data.canWrite}
						<form method="POST" action="?/remove" class="ml-auto">
							<input type="hidden" name="pattern_id" value={pattern.id} />
							<ConfirmButton label="Remove" tone="neutral" />
						</form>
					{/if}
				</li>
			{/each}
		</ul>
	{/if}
</div>

{#if data.canWrite}
	<form method="POST" action="?/add" class="mt-4 rounded-lg border border-slate-200 bg-white p-4">
		<Field
			label="Add allowed senders"
			name="patterns"
			hint="One per line. Checked against the real grammar when you submit."
		>
			{#snippet children({ id, describedBy })}
				<textarea
					{id}
					name="patterns"
					rows="2"
					aria-describedby={describedBy}
					class="w-full rounded-md border border-slate-300 px-3 py-1.5 font-mono text-sm"
					>{values.patterns ?? ''}</textarea
				>
			{/snippet}
		</Field>
		<button
			type="submit"
			class="mt-3 rounded-md bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700"
		>
			Add
		</button>
	</form>
{/if}

<h2 class="mt-8 text-sm font-semibold tracking-wide text-slate-500 uppercase">Check a pattern</h2>
<p class="mt-1 max-w-prose text-sm text-slate-500">
	Both checks below run against the same Go code that authorises a real submission, so the answer
	here is the answer at send time.
</p>

<div class="mt-3 grid gap-4 sm:grid-cols-2">
	<form method="POST" action="?/validate" class="rounded-lg border border-slate-200 bg-white p-4">
		<Field
			label="Is this pattern valid?"
			name="pattern"
			hint="Shows the canonical form that would be stored."
		>
			{#snippet children({ id, describedBy })}
				<input
					{id}
					name="pattern"
					placeholder="*@Exemplé.COM"
					aria-describedby={describedBy}
					class="w-full rounded-md border border-slate-300 px-3 py-1.5 font-mono text-sm"
				/>
			{/snippet}
		</Field>
		<button
			type="submit"
			class="mt-3 rounded-md border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50"
		>
			Validate
		</button>

		{#if validation}
			<div
				class="mt-3 rounded-md border px-3 py-2 text-sm {validation.valid
					? 'border-emerald-200 bg-emerald-50 text-emerald-900'
					: 'border-rose-200 bg-rose-50 text-rose-900'}"
			>
				{#if validation.valid}
					Stored as <code class="font-mono text-xs">{validation.normalized}</code>.
					<span class="block text-xs">{validation.explanation}</span>
				{:else}
					{validation.error}
				{/if}
			</div>
		{/if}
	</form>

	<form method="POST" action="?/test" class="rounded-lg border border-slate-200 bg-white p-4">
		<Field
			label="Could this credential send as…?"
			name="address"
			hint="Also answers whether any enabled domain routes it."
		>
			{#snippet children({ id, describedBy })}
				<input
					{id}
					name="address"
					placeholder="alerts@example.com"
					aria-describedby={describedBy}
					class="w-full rounded-md border border-slate-300 px-3 py-1.5 font-mono text-sm"
				/>
			{/snippet}
		</Field>
		<button
			type="submit"
			class="mt-3 rounded-md border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50"
		>
			Test
		</button>

		{#if test}
			<div
				class="mt-3 space-y-1 rounded-md border px-3 py-2 text-sm {test.allowed &&
				test.routable_domain
					? 'border-emerald-200 bg-emerald-50 text-emerald-900'
					: 'border-amber-200 bg-amber-50 text-amber-900'}"
			>
				<p>
					{#if test.allowed}
						Allowed by <code class="font-mono text-xs">{test.matched_pattern}</code>.
					{:else}
						Not allowed: no pattern on this credential matches.
					{/if}
				</p>
				<p>
					{#if test.routable_domain}
						Routes via <strong>{test.backend_name}</strong>.
					{:else}
						<!-- The half an operator forgets: allowed and unroutable looks like a
						     working setup until nothing arrives. -->
						No enabled domain routes this address, so it would be rejected even though the pattern allows
						it.
					{/if}
				</p>
			</div>
		{/if}
	</form>
</div>
