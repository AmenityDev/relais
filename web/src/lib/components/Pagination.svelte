<script lang="ts">
	// Keyset pagination: there is a next page or there is not, and there is no page
	// count. Offering numbered pages would imply a total the API deliberately does
	// not compute.
	//
	// The caller passes an already-resolved path rather than letting this component
	// build one from a query string alone. That keeps it reusable across lists while
	// still going through resolve(), so a renamed route is a build error here too.
	let {
		nextCursor,
		path,
		params = {}
	}: {
		nextCursor: string | undefined;
		path: string;
		/** Filters to carry over, so paging does not silently drop them. */
		params?: Record<string, string>;
	} = $props();

	const href = $derived.by(() => {
		const pairs = Object.entries(params).map(
			([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`
		);
		if (nextCursor !== undefined) pairs.push(`cursor=${encodeURIComponent(nextCursor)}`);
		return pairs.length === 0 ? path : `${path}?${pairs.join('&')}`;
	});
</script>

{#if nextCursor}
	<nav class="flex items-center justify-end gap-2 pt-3" aria-label="Pagination">
		<a
			{href}
			class="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm hover:bg-slate-50"
		>
			Older →
		</a>
	</nav>
{/if}
