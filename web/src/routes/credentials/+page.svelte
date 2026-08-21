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

	// Creation and rotation return the same show-once payload, and the page treats
	// them the same way: the secret is on screen for this render only, so the create
	// form gives way to it rather than sitting above it inviting a navigation.
	const issued = $derived(
		form && 'created' in form ? form.created : form && 'rotated' in form ? form.rotated : undefined
	);

	const rotateWarning =
		'The current secret stops working immediately. Whatever is using it will fail to send ' +
		'until it is reconfigured with the new one.';
	const revokeWarning =
		'Revoking is permanent and cannot be undone by creating a secret later. The credential ' +
		'row stays, so the messages it sent keep naming it.';
	const deleteWarning =
		'Deleting removes the credential entirely. The messages it sent are kept, but they stop ' +
		'naming it, so the audit trail loses who submitted them. To cut off access and keep the ' +
		'trail, revoke instead.';
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

{#if issued}
	<div class="mt-4">
		<p class="mb-2 text-sm text-slate-600">
			Secret for <span class="font-medium">{issued.credential.name}</span>.
		</p>
		<CopyOnce secret={issued.secret} username={issued.username} />
		{#if issued.warning}
			<p class="mt-2 text-sm text-amber-800">{issued.warning}</p>
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
						{#if data.canWrite}
							<!-- One form, several formactions: three of these four buttons submit the
							     same id to different endpoints, and a form each would only give the
							     hidden input three places to fall out of step. -->
							<form method="POST" class="flex flex-wrap justify-end gap-2">
								<input type="hidden" name="id" value={credential.id} />

								{#if credential.state !== 'revoked'}
									<button
										type="button"
										onclick={() => (editing = credential.id)}
										class="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm hover:bg-slate-50"
									>
										Edit
									</button>
									<!-- Rotating keeps the credential and replaces only what leaked: the
									     id, name, limits and allowed senders survive, so past messages
									     keep their attribution and nothing has to be re-reviewed. -->
									<ConfirmButton
										label="Rotate"
										formaction="?/rotate"
										tone="neutral"
										confirm={credential.name}
										warning={rotateWarning}
									/>
									<!-- Revocation is irreversible and deliberately not a delete: the
									     messages this credential sent keep pointing at it, which is what
									     makes an audit possible. -->
									<ConfirmButton
										label="Revoke"
										formaction="?/revoke"
										confirm={credential.name}
										warning={revokeWarning}
									/>
								{/if}

								<!-- Offered on a revoked credential too, which is where it is mostly
								     wanted: clearing out a row whose history nobody needs. -->
								<ConfirmButton
									label="Delete"
									formaction="?/delete"
									confirm={credential.name}
									warning={deleteWarning}
								/>
							</form>
						{/if}

						{#if data.canWrite && credential.state !== 'revoked'}
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
