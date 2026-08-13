<script lang="ts">
	import { resolve } from '$app/paths';

	// The secret is shown once and is not recoverable (F7). relais stores a peppered
	// HMAC of it and cannot show it again, so this component's job is to make that
	// unmistakable before the operator navigates away.
	//
	// The acknowledgement is required rather than advisory: without it, the usual
	// outcome is a closed tab and a credential nobody has.
	// `username?: string | undefined` rather than `username?: string`: under
	// exactOptionalPropertyTypes an optional property does not accept an explicit
	// undefined, and the API returns the field absent for an api_key credential.
	let { secret, username }: { secret: string; username?: string | undefined } = $props();

	let copied = $state(false);
	let acknowledged = $state(false);
	let revealed = $state(false);

	async function copy() {
		try {
			await navigator.clipboard.writeText(secret);
			copied = true;
		} catch {
			// Clipboard access can be refused; the value is on screen either way, so
			// reveal it rather than leaving the operator with a button that did nothing.
			revealed = true;
		}
	}
</script>

<div class="space-y-3 rounded-lg border border-amber-300 bg-amber-50 p-4">
	<p class="text-sm font-medium text-amber-900">
		This is the only time this secret is shown. relais cannot display it again.
	</p>

	{#if username}
		<div class="space-y-1">
			<p class="text-xs font-medium tracking-wide text-amber-900 uppercase">Username</p>
			<code class="block rounded bg-white px-3 py-2 font-mono text-sm break-all">{username}</code>
		</div>
	{/if}

	<div class="space-y-1">
		<p class="text-xs font-medium tracking-wide text-amber-900 uppercase">Secret</p>
		<code class="block rounded bg-white px-3 py-2 font-mono text-sm break-all">
			{revealed ? secret : '•'.repeat(Math.min(secret.length, 48))}
		</code>
	</div>

	<div class="flex flex-wrap items-center gap-2">
		<button
			type="button"
			onclick={copy}
			class="rounded-md bg-amber-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-amber-950"
		>
			{copied ? 'Copied' : 'Copy to clipboard'}
		</button>
		{#if !revealed}
			<button
				type="button"
				onclick={() => (revealed = true)}
				class="rounded-md border border-amber-300 bg-white px-3 py-1.5 text-sm hover:bg-amber-100"
			>
				Reveal
			</button>
		{/if}
	</div>

	<label class="flex items-start gap-2 text-sm text-amber-900">
		<input type="checkbox" bind:checked={acknowledged} class="mt-0.5" />
		<span>I have stored this secret somewhere safe.</span>
	</label>

	<a
		href={resolve('/credentials')}
		aria-disabled={!acknowledged}
		tabindex={acknowledged ? 0 : -1}
		class="inline-flex rounded-md px-3 py-1.5 text-sm font-medium {acknowledged
			? 'bg-brand-600 text-white hover:bg-brand-700'
			: 'pointer-events-none bg-slate-200 text-slate-500'}"
	>
		Done
	</a>
</div>
