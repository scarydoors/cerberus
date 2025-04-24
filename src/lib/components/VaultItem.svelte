<script lang="ts">
import type { HTMLButtonAttributes } from 'svelte/elements';
type ItemPreview = {
  id: number;
  name: string;
  site: string;
};

type Props = {
  preview: ItemPreview;
  isSelected?: boolean;
  onclick?: HTMLButtonAttributes['onclick'];
};

const { preview, isSelected = true, onclick }: Props = $props();
</script>

<button
  class={[
    'block w-full rounded-md px-4 py-1 text-left',
    isSelected ? 'bg-blue-700 hover:bg-blue-800' : 'hover:bg-neutral-800'
  ]}
  {onclick}
>
  <div class="font-bold">
    {preview.name}
  </div>
  <div class={["text-sm", isSelected || "text-neutral-400"]}>
    {preview.site}
  </div>
</button>
