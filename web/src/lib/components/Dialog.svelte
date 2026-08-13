<script lang="ts">
	// The native <dialog>, which is the reason this project needs no component
	// library (F4). It brings the focus trap, Escape to close, the inert backdrop and
	// the correct ARIA role — the four things that are hard to get right by hand and
	// are the usual argument for adopting one.
	let {
		open = false,
		title,
		children,
		footer,
		onclose
	}: {
		open?: boolean;
		title: string;
		children: import('svelte').Snippet;
		footer?: import('svelte').Snippet;
		/**
		 * Called whenever the dialog closes, including via Escape or the backdrop.
		 * Without it a caller driving `open` from its own state would never learn the
		 * dialog was dismissed, and the row could not be reopened.
		 */
		onclose?: () => void;
	} = $props();

	let element: HTMLDialogElement | undefined = $state();

	$effect(() => {
		if (element === undefined) return;
		if (open && !element.open) element.showModal();
		if (!open && element.open) element.close();
	});
</script>

<dialog
	bind:this={element}
	onclose={() => onclose?.()}
	class="w-full max-w-lg rounded-lg border border-slate-200 bg-white p-0 shadow-xl backdrop:bg-slate-900/40"
	aria-labelledby="dialog-title"
>
	<div class="border-b border-slate-200 px-5 py-3">
		<h2 id="dialog-title" class="text-base font-semibold">{title}</h2>
	</div>
	<div class="px-5 py-4">{@render children()}</div>
	{#if footer}
		<div class="flex justify-end gap-2 border-t border-slate-200 bg-slate-50 px-5 py-3">
			{@render footer()}
		</div>
	{/if}
</dialog>
