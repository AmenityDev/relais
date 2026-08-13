<script lang="ts">
	// Tone is a closed set rather than a free class string, so a status can never be
	// rendered in a colour that contradicts what it means.
	type Tone = 'neutral' | 'good' | 'warn' | 'bad' | 'info';

	let { tone = 'neutral', children }: { tone?: Tone; children: import('svelte').Snippet } =
		$props();

	const tones: Record<Tone, string> = {
		neutral: 'bg-slate-100 text-slate-700 ring-slate-200',
		good: 'bg-emerald-50 text-emerald-800 ring-emerald-200',
		warn: 'bg-amber-50 text-amber-900 ring-amber-200',
		bad: 'bg-rose-50 text-rose-800 ring-rose-200',
		info: 'bg-brand-50 text-brand-700 ring-brand-100'
	};
</script>

<span
	class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset {tones[
		tone
	]}"
>
	{@render children()}
</span>
