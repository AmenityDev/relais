<script lang="ts">
	// A destructive action inside a form, gated by a typed confirmation for the ones
	// that cannot be undone. `formaction` lets several of these share one form.
	let {
		label,
		confirm,
		formaction,
		disabled = false,
		tone = 'danger'
	}: {
		label: string;
		/** When set, the click is refused unless the operator types this exactly. */
		confirm?: string;
		formaction?: string;
		disabled?: boolean;
		tone?: 'danger' | 'neutral';
	} = $props();

	function guard(event: MouseEvent) {
		if (confirm === undefined) return;
		const typed = window.prompt(`Type ${confirm} to confirm. This cannot be undone.`);
		if (typed !== confirm) event.preventDefault();
	}
</script>

<button
	type="submit"
	{formaction}
	{disabled}
	onclick={guard}
	class="rounded-md px-3 py-1.5 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50 {tone ===
	'danger'
		? 'border border-rose-300 bg-white text-rose-700 hover:bg-rose-50'
		: 'border border-slate-300 bg-white text-slate-700 hover:bg-slate-50'}"
>
	{label}
</button>
