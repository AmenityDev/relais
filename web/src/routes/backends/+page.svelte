<script lang="ts">
	import Badge from '$lib/components/Badge.svelte';
	import ConfirmButton from '$lib/components/ConfirmButton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import Field from '$lib/components/Field.svelte';
	import Table from '$lib/components/Table.svelte';
	import type { ActionData, PageData } from './$types';

	let { data, form }: { data: PageData; form: ActionData } = $props();

	let showCreate = $state(false);

	const values = $derived((form && 'values' in form ? form.values : {}) as Record<string, string>);
	const probe = $derived(form && 'probe' in form ? form.probe : undefined);
</script>

<svelte:head><title>relais — relays</title></svelte:head>

<div class="flex flex-wrap items-center gap-3">
	<h1 class="text-xl font-semibold">Relays</h1>
	{#if data.canWrite}
		<button
			type="button"
			onclick={() => (showCreate = !showCreate)}
			class="ml-auto rounded-md bg-brand-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-700"
		>
			{showCreate ? 'Cancel' : 'Register a relay'}
		</button>
	{/if}
</div>

<p class="mt-1 max-w-prose text-sm text-slate-500">
	Where relais hands mail on. DKIM signing happens downstream, at the relay — relais authenticates
	the sender and passes the message along.
</p>

{#if form && 'message' in form && form.message}
	<p
		class="mt-4 rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-800"
		role="alert"
	>
		{form.message}
	</p>
{/if}

{#if probe}
	<div
		class="mt-4 rounded-md border px-3 py-2 text-sm {probe.result.ok
			? 'border-emerald-200 bg-emerald-50 text-emerald-900'
			: 'border-rose-200 bg-rose-50 text-rose-900'}"
	>
		{#if probe.result.ok}
			Connected{probe.result.used_tls ? ' over TLS' : ' without TLS'}{probe.result.authenticated
				? ' and authenticated'
				: ''}.
			{#if probe.result.extensions?.length}
				<span class="text-xs">Offered: {probe.result.extensions.join(', ')}</span>
			{/if}
		{:else}
			The relay refused: {probe.result.error?.detail ?? probe.result.error?.code ?? 'unknown error'}
		{/if}
	</div>
{/if}

{#if showCreate}
	<form
		method="POST"
		action="?/create"
		class="mt-4 grid gap-4 rounded-lg border border-slate-200 bg-white p-4 sm:grid-cols-2"
	>
		<Field label="Name" name="name" required hint="How this relay is referred to elsewhere.">
			{#snippet children({ id, describedBy })}
				<input
					{id}
					name="name"
					value={values.name ?? ''}
					required
					aria-describedby={describedBy}
					class="w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm"
				/>
			{/snippet}
		</Field>

		<Field label="Host" name="host" required>
			{#snippet children({ id, describedBy })}
				<input
					{id}
					name="host"
					value={values.host ?? ''}
					required
					aria-describedby={describedBy}
					class="w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm"
				/>
			{/snippet}
		</Field>

		<Field label="Port" name="port" required>
			{#snippet children({ id, describedBy })}
				<input
					{id}
					name="port"
					type="number"
					min="1"
					max="65535"
					value={values.port ?? '587'}
					required
					aria-describedby={describedBy}
					class="w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm"
				/>
			{/snippet}
		</Field>

		<Field
			label="Transport"
			name="tls_mode"
			hint="starttls upgrades an open connection; tls connects encrypted from the first byte."
		>
			{#snippet children({ id, describedBy })}
				<select
					{id}
					name="tls_mode"
					aria-describedby={describedBy}
					class="w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm"
				>
					<option
						value="starttls"
						selected={values.tls_mode !== 'tls' && values.tls_mode !== 'none'}
					>
						starttls
					</option>
					<option value="tls" selected={values.tls_mode === 'tls'}>tls</option>
					<option value="none" selected={values.tls_mode === 'none'}>none (no credentials)</option>
				</select>
			{/snippet}
		</Field>

		<Field
			label="Username"
			name="auth_user"
			hint="Leave empty for a relay that takes no credentials."
		>
			{#snippet children({ id, describedBy })}
				<input
					{id}
					name="auth_user"
					value={values.auth_user ?? ''}
					autocomplete="off"
					aria-describedby={describedBy}
					class="w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm"
				/>
			{/snippet}
		</Field>

		<Field
			label="Password"
			name="password"
			hint="Stored sealed with AES-256-GCM. No endpoint ever returns it, so it cannot be shown again."
		>
			{#snippet children({ id, describedBy })}
				<input
					{id}
					name="password"
					type="password"
					autocomplete="new-password"
					aria-describedby={describedBy}
					class="w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm"
				/>
			{/snippet}
		</Field>

		<div class="sm:col-span-2">
			<button
				type="submit"
				class="rounded-md bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700"
			>
				Register
			</button>
		</div>
	</form>
{/if}

<div class="mt-6">
	{#if data.backends.length === 0}
		<EmptyState
			title="No relays yet"
			hint="Add the SMTP relay that carries your mail — OCI Email Delivery, or mailpit for local testing."
		/>
	{:else}
		<Table
			columns={['Name', 'Address', 'Transport', 'Auth', 'State', '']}
			rows={data.backends}
			caption="Configured SMTP relays"
		>
			{#snippet row(backend)}
				<tr>
					<td class="px-4 py-2.5 font-medium">{backend.name}</td>
					<td class="px-4 py-2.5 font-mono text-xs">{backend.host}:{backend.port}</td>
					<td class="px-4 py-2.5">
						<Badge tone={backend.tls_mode === 'none' ? 'warn' : 'good'}>{backend.tls_mode}</Badge>
					</td>
					<td class="px-4 py-2.5 text-xs">
						{#if backend.auth_user}
							{backend.auth_user}
							{#if !backend.has_password}
								<span class="ml-1 text-amber-700">(no password)</span>
							{/if}
						{:else}
							<span class="text-slate-400">none</span>
						{/if}
					</td>
					<td class="px-4 py-2.5">
						{#if backend.enabled}
							<Badge tone="good">enabled</Badge>
						{:else}
							<!-- A domain pointing here delivers nothing, so this is not a neutral
							     state to render quietly. -->
							<Badge tone="bad">disabled</Badge>
						{/if}
					</td>
					<td class="px-4 py-2.5 text-right">
						{#if data.canWrite}
							<form method="POST" class="flex justify-end gap-2">
								<input type="hidden" name="id" value={backend.id} />
								<ConfirmButton label="Test" formaction="?/probe" tone="neutral" />
								<ConfirmButton label="Remove" formaction="?/remove" confirm={backend.name} />
							</form>
						{/if}
					</td>
				</tr>
			{/snippet}
		</Table>
	{/if}
</div>
