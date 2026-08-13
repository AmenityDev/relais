<script lang="ts">
	// A label, its control, an optional explanation and an error, wired together so
	// the error is announced rather than only coloured.
	let {
		label,
		name,
		hint,
		error,
		required = false,
		children
	}: {
		label: string;
		name: string;
		hint?: string;
		error?: string | undefined;
		required?: boolean;
		children: import('svelte').Snippet<[{ id: string; describedBy: string | undefined }]>;
	} = $props();

	// Derived, not const: props are reactive, and a plain const would capture only
	// the value this component was created with — so an error appearing after the
	// first render would never be wired to aria-describedby.
	const id = $derived(`field-${name}`);
	const hintId = $derived(hint ? `${id}-hint` : undefined);
	const errorId = $derived(error ? `${id}-error` : undefined);
	const describedBy = $derived([hintId, errorId].filter(Boolean).join(' ') || undefined);
</script>

<div class="space-y-1">
	<label for={id} class="block text-sm font-medium text-slate-900">
		{label}
		{#if required}<span class="text-rose-600" aria-hidden="true">*</span>{/if}
	</label>
	{@render children({ id, describedBy })}
	{#if hint}<p id={hintId} class="text-xs text-slate-500">{hint}</p>{/if}
	{#if error}
		<p id={errorId} class="text-xs font-medium text-rose-700" role="alert">{error}</p>
	{/if}
</div>
