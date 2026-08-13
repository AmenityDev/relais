<script lang="ts" generics="Row">
	// Markup and classes, no logic. A wide table scrolls inside its own container so
	// the page itself never scrolls sideways.
	let {
		columns,
		rows,
		row,
		caption
	}: {
		columns: readonly string[];
		rows: readonly Row[];
		row: import('svelte').Snippet<[Row]>;
		caption?: string;
	} = $props();
</script>

<div class="overflow-x-auto rounded-lg border border-slate-200 bg-white">
	<table class="min-w-full divide-y divide-slate-200 text-sm">
		{#if caption}<caption class="sr-only">{caption}</caption>{/if}
		<thead class="bg-slate-50">
			<tr>
				{#each columns as column (column)}
					<th scope="col" class="px-4 py-2.5 text-left font-semibold text-slate-700">{column}</th>
				{/each}
			</tr>
		</thead>
		<tbody class="divide-y divide-slate-100">
			{#each rows as item (item)}
				{@render row(item)}
			{/each}
		</tbody>
	</table>
</div>
