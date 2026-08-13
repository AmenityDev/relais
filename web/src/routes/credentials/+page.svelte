<script lang="ts">
	import { resolve } from '$app/paths';
	import Badge from '$lib/components/Badge.svelte';
	import ConfirmButton from '$lib/components/ConfirmButton.svelte';
	import CopyOnce from '$lib/components/CopyOnce.svelte';
	import Dialog from '$lib/components/Dialog.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import Field from '$lib/components/Field.svelte';
	import Table from '$lib/components/Table.svelte';
	import type { ActionData, PageData } from './$types';

	let { data, form }: { data: PageData; form: ActionData } = $props();

	const created = $derived(form && 'created' in form ? form.created : undefined);
	const values = $derived((form && 'values' in form ? form.values : {}) as Record<string, string>);
	let editing = $state<string | undefined>(undefined);
</script>

<svelte:head><title>relais — credentials</title></svelte:head>

<h1 class="text-xl font-semibold">Credentials</h1>
<p class="mt-1 max-w-prose text-sm text-slate-500">
	What an application presents to send mail, and the addresses it is allowed to send as. relais
	stores a peppered HMAC of the secret, never the secret itself.
</p>

{#if form && 'message' in form && form.message}
	<p
		class="mt-4 rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-800"
		role="alert"
	>
		{form.message}
	</p>
{/if}

{#if created}
	<div class="mt-4">
		<CopyOnce secret={created.secret} username={created.username} />
		{#if created.warning}
			<p class="mt-2 text-sm text-amber-800">{created.warning}</p>
		{/if}
	</div>
{:else if data.canWrite}
	<form
		method="POST"
		action="?/create"
		class="mt-6 grid gap-4 rounded-lg border border-slate-200 bg-white p-4 sm:grid-cols-2"
	>
		<Field label="Name" name="name" required hint="Which application this is for.">
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

		<Field
			label="Type"
			name="type"
			hint="api_key for the REST API; smtp_user for an application that speaks SMTP."
		>
			{#snippet children({ id, describedBy })}
				<select
					{id}
					name="type"
					aria-describedby={describedBy}
					class="w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm"
				>
					<option value="api_key" selected={values.type !== 'smtp_user'}>api_key</option>
					<option value="smtp_user" selected={values.type === 'smtp_user'}>smtp_user</option>
				</select>
			{/snippet}
		</Field>

		<div class="sm:col-span-2">
			<Field
				label="Allowed senders"
				name="patterns"
				hint="One per line. Four shapes: an exact address, *@example.com, *@*.example.com, or *. Note that *@*.example.com does NOT cover example.com — the grammar is checked by relais, not here."
			>
				{#snippet children({ id, describedBy })}
					<textarea
						{id}
						name="patterns"
						rows="3"
						aria-describedby={describedBy}
						class="w-full rounded-md border border-slate-300 px-3 py-1.5 font-mono text-sm"
						placeholder="alerts@example.com&#10;*@notifications.example.com"
						>{values.patterns ?? ''}</textarea
					>
				{/snippet}
			</Field>
		</div>

		<div class="sm:col-span-2">
			<button
				type="submit"
				class="rounded-md bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700"
			>
				Create credential
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
	{#if data.credentials.length === 0}
		<EmptyState title="No credentials" hint="Create one for each application that sends mail." />
	{:else}
		<Table
			columns={['Name', 'Type', 'Senders', 'State', '']}
			rows={data.credentials}
			caption="Sending credentials"
		>
			{#snippet row(credential)}
				<tr>
					<td class="px-4 py-2.5 font-medium">
						<a
							href={resolve('/credentials/[id]', { id: credential.id })}
							class="text-brand-700 hover:underline"
						>
							{credential.name}
						</a>
					</td>
					<td class="px-4 py-2.5 text-xs">{credential.type}</td>
					<td class="px-4 py-2.5">
						{#if credential.pattern_count === 0}
							<!-- Not a row like every other: this credential can send as nobody, and
							     every attempt it makes will be rejected. -->
							<Badge tone="warn">no allowed sender</Badge>
						{:else}
							<span class="text-sm">{credential.pattern_count}</span>
						{/if}
					</td>
					<td class="px-4 py-2.5">
						<Badge
							tone={credential.state === 'active'
								? 'good'
								: credential.state === 'revoked'
									? 'bad'
									: 'neutral'}
						>
							{credential.state}
						</Badge>
					</td>
					<td class="px-4 py-2.5 text-right">
						{#if data.canWrite && credential.state !== 'revoked'}
							<div class="flex flex-wrap justify-end gap-2">
								<button
									type="button"
									onclick={() => (editing = credential.id)}
									class="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm hover:bg-slate-50"
								>
									Edit
								</button>
								<form method="POST" action="?/revoke">
									<input type="hidden" name="id" value={credential.id} />
									<!-- Revocation is irreversible and deliberately not a delete: the
									     messages this credential sent keep pointing at it, which is what
									     makes an audit possible. -->
									<ConfirmButton label="Revoke" confirm={credential.name} />
								</form>
							</div>

							<Dialog
								open={editing === credential.id}
								title="Edit {credential.name}"
								onclose={() => (editing = undefined)}
							>
								<form
									method="POST"
									action="?/update"
									id="edit-{credential.id}"
									class="grid gap-3 text-left"
								>
									<input type="hidden" name="id" value={credential.id} />

									<label class="block text-sm">
										<span class="font-medium">Name</span>
										<input
											name="name"
											value={credential.name}
											required
											class="mt-1 w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm"
										/>
									</label>

									<div class="grid grid-cols-2 gap-3">
										<label class="block text-sm">
											<span class="font-medium">Rate limit (per second)</span>
											<input
												name="rate_limit_rps"
												type="number"
												step="0.1"
												min="0.1"
												value={credential.rate_limit_rps ?? ''}
												placeholder="deployment default"
												class="mt-1 w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm"
											/>
										</label>
										<label class="block text-sm">
											<span class="font-medium">Burst</span>
											<input
												name="rate_limit_burst"
												type="number"
												min="1"
												value={credential.rate_limit_burst ?? ''}
												placeholder="deployment default"
												class="mt-1 w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm"
											/>
										</label>
									</div>
									<p class="text-xs text-slate-500">
										Leave both empty to use the deployment default. The limit is per process, which
										is documented and deliberate for a single-instance deployment.
									</p>

									<label class="flex items-center gap-2 text-sm">
										<input type="checkbox" name="enabled" checked={credential.state === 'active'} />
										<span>
											Enabled
											<span class="block text-xs text-slate-500">
												Disabling is reversible; revoking is not.
											</span>
										</span>
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
										form="edit-{credential.id}"
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
