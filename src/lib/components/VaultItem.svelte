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
        "py-1 px-4 rounded-md text-left block w-full",
        isSelected ? "hover:bg-blue-800 bg-blue-900" : "hover:bg-neutral-800",
        ]}
  {onclick}>
  <div class="font-bold">
    {preview.name}
  </div>
  <div class="text-sm text-neutral-400">
    {preview.site}
  </div>
</button>
