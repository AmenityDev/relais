<script lang="ts">
	import Badge from '$lib/components/Badge.svelte';
	import ConfirmButton from '$lib/components/ConfirmButton.svelte';
	import Dialog from '$lib/components/Dialog.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import Field from '$lib/components/Field.svelte';
	import Table from '$lib/components/Table.svelte';
	import type { ActionData, PageData } from './$types';

	let { data, form }: { data: PageData; form: ActionData } = $props();
	const values = $derived((form && 'values' in form ? form.values : {}) as Record<string, string>);
	let editing = $state<string | undefined>(undefined);
</script>

<svelte:head><title>relais — domains</title></svelte:head>

<h1 class="text-xl font-semibold">Sending domains</h1>
<p class="mt-1 max-w-prose text-sm text-slate-500">
	Which relay carries mail for which domain. A credential may be allowed to send as an address that
	no domain routes — the check below answers both halves.
</p>

{#if form && 'message' in form && form.message}
	<p
		class="mt-4 rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-800"
		role="alert"
	>
		{form.message}
	</p>
{/if}

<form method="GET" class="mt-6 flex flex-wrap items-end gap-2">
	<div class="grow sm:max-w-sm">
		<Field label="Which relay would carry this sender?" name="sender">
			{#snippet children({ id, describedBy })}
				<input
					{id}
					name="sender"
					value={data.sender}
					placeholder="alerts@mail.example.com"
					aria-describedby={describedBy}
					class="w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm"
				/>
			{/snippet}
		</Field>
	</div>
	<button
		type="submit"
		class="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm hover:bg-slate-50"
	>
		Check
	</button>
</form>

{#if data.resolved}
	<div
		class="mt-3 rounded-md border px-3 py-2 text-sm {data.resolved.resolved
			? 'border-emerald-200 bg-emerald-50 text-emerald-900'
			: 'border-amber-200 bg-amber-50 text-amber-900'}"
	>
		{#if data.resolved.resolved}
			<code class="font-mono text-xs">{data.resolved.sender}</code> routes via
			<strong>{data.resolved.backend_name}</strong>
			({data.resolved.backend_address}, {data.resolved.tls_mode}{data.resolved.uses_auth
				? ', authenticated'
				: ''}) through the domain <strong>{data.resolved.domain_name}</strong>.
		{:else}
			Nothing routes <code class="font-mono text-xs">{data.resolved.sender}</code>.
			{data.resolved.reason}
		{/if}
	</div>
{/if}

{#if data.canWrite}
	<form
		method="POST"
		action="?/create"
		class="mt-6 grid gap-4 rounded-lg border border-slate-200 bg-white p-4 sm:grid-cols-3"
	>
		<Field label="Domain" name="name" required>
			{#snippet children({ id, describedBy })}
				<input
					{id}
					name="name"
					value={values.name ?? ''}
					required
					placeholder="example.com"
					aria-describedby={describedBy}
					class="w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm"
				/>
			{/snippet}
		</Field>

		<Field label="Relay" name="backend_id" required>
			{#snippet children({ id, describedBy })}
				<select
					{id}
					name="backend_id"
					required
					aria-describedby={describedBy}
					class="w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm"
				>
					{#each data.backends as backend (backend.id)}
						<option value={backend.id} selected={values.backend_id === backend.id}>
							{backend.name}{backend.enabled ? '' : ' (disabled)'}
						</option>
					{/each}
				</select>
			{/snippet}
		</Field>

		<div class="flex flex-col justify-end gap-2">
			<label class="flex items-start gap-2 text-sm">
				<input type="checkbox" name="include_subdomains" class="mt-0.5" />
				<span>
					Include subdomains
					<span class="block text-xs text-slate-500">
						Covers mail.example.com. Without it, only example.com itself routes.
					</span>
				</span>
			</label>
			<button
				type="submit"
				class="rounded-md bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700"
			>
				Add domain
			</button>
		</div>
	</form>
{/if}

{#if data.truncated}
	<p class="mt-4 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
		The API reported more rows than are shown here: this list is not all rows. Paging is not
		implemented for this screen — see docs/FRONTEND.md.
	</p>
{/if}

<div class="mt-6">
	{#if data.domains.length === 0}
		<EmptyState title="No sending domains" hint="Add the domain your applications send from." />
	{:else}
		<Table
			columns={['Domain', 'Relay', 'Subdomains', 'State', '']}
			rows={data.domains}
			caption="Sending domains"
		>
			{#snippet row(domain)}
				<tr>
					<td class="px-4 py-2.5 font-medium">{domain.name}</td>
					<td class="px-4 py-2.5 text-sm">
						{domain.backend_name}
						{#if domain.backend_enabled === false}
							<!-- This is the state that generates support tickets: everything looks
							     configured and nothing is delivered. -->
							<Badge tone="bad">relay disabled — delivers nothing</Badge>
						{/if}
					</td>
					<td class="px-4 py-2.5 text-sm">
						{#if domain.include_subdomains}<Badge tone="info">included</Badge>{:else}
							<span class="text-slate-400">exact only</span>
						{/if}
					</td>
					<td class="px-4 py-2.5">
						{#if domain.enabled}<Badge tone="good">enabled</Badge>{:else}
							<Badge tone="bad">disabled</Badge>
						{/if}
					</td>
					<td class="px-4 py-2.5 text-right">
						{#if data.canWrite}
							<div class="flex flex-wrap justify-end gap-2">
								<form method="POST" action="?/toggle">
									<input type="hidden" name="id" value={domain.id} />
									<input type="hidden" name="enabled" value={domain.enabled ? 'false' : 'true'} />
									<button
										type="submit"
										class="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm hover:bg-slate-50"
									>
										{domain.enabled ? 'Disable' : 'Enable'}
									</button>
								</form>
								<button
									type="button"
									onclick={() => (editing = domain.id)}
									class="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm hover:bg-slate-50"
								>
									Edit
								</button>
								<form method="POST" action="?/remove">
									<input type="hidden" name="id" value={domain.id} />
									<ConfirmButton label="Remove" confirm={domain.name} />
								</form>
							</div>

							<Dialog
								open={editing === domain.id}
								title="Edit {domain.name}"
								onclose={() => (editing = undefined)}
							>
								<form
									method="POST"
									action="?/update"
									id="edit-{domain.id}"
									class="grid gap-3 text-left"
								>
									<input type="hidden" name="id" value={domain.id} />

									<label class="block text-sm">
										<span class="font-medium">Domain</span>
										<input
											name="name"
											value={domain.name}
											required
											class="mt-1 w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm"
										/>
									</label>

									<label class="block text-sm">
										<span class="font-medium">Relay</span>
										<select
											name="backend_id"
											required
											class="mt-1 w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm"
										>
											{#each data.backends as candidate (candidate.id)}
												<option
													value={candidate.id}
													selected={candidate.name === domain.backend_name}
												>
													{candidate.name}{candidate.enabled ? '' : ' (disabled)'}
												</option>
											{/each}
										</select>
										<!-- Repointing here is the recovery move when a relay goes bad. -->
										<span class="mt-1 block text-xs text-slate-500">
											Mail for this domain is handed to the selected relay.
										</span>
									</label>

									<label class="flex items-start gap-2 text-sm">
										<input
											type="checkbox"
											name="include_subdomains"
											checked={domain.include_subdomains}
											class="mt-0.5"
										/>
										<span>
											Include subdomains
											<span class="block text-xs text-slate-500">
												Covers mail.{domain.name}. Without it, only {domain.name} itself routes.
											</span>
										</span>
									</label>

									<label class="flex items-center gap-2 text-sm">
										<input type="checkbox" name="enabled" checked={domain.enabled} />
										<span>Enabled</span>
									</label>
								</form>

								{#snippet footer()}
									<button
										type="button"
										onclick={() => (editing = undefined)}
										class="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm hover:bg-slate-50"
									>
										Cancel
									</button>
									<button
										type="submit"
										form="edit-{domain.id}"
										class="rounded-md bg-brand-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-brand-700"
									>
										Save
									</button>
								{/snippet}
							</Dialog>
						{/if}
					</td>
				</tr>
			{/snippet}
		</Table>
	{/if}
</div>
