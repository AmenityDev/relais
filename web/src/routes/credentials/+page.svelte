<script lang="ts">
	import { resolve } from '$app/paths';
	import Badge from '$lib/components/Badge.svelte';
	import ConfirmButton from '$lib/components/ConfirmButton.svelte';
	import CopyOnce from '$lib/components/CopyOnce.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import Field from '$lib/components/Field.svelte';
	import Table from '$lib/components/Table.svelte';
	import type { ActionData, PageData } from './$types';

	let { data, form }: { data: PageData; form: ActionData } = $props();

	const created = $derived(form && 'created' in form ? form.created : undefined);
	const values = $derived((form && 'values' in form ? form.values : {}) as Record<string, string>);
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
						{#if data.canWrite && credential.state === 'active'}
							<form method="POST" action="?/revoke" class="flex justify-end">
								<input type="hidden" name="id" value={credential.id} />
								<ConfirmButton label="Revoke" confirm={credential.name} />
							</form>
						{/if}
					</td>
				</tr>
			{/snippet}
		</Table>
	{/if}
</div>
