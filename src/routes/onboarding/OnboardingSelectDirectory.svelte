<script lang="ts">
import { open } from '@tauri-apps/plugin-dialog';

type Props = {
  directory: string;
  valid: boolean;
};

let { directory = $bindable(), valid = $bindable() }: Props = $props();

async function openFile() {
  const file = await open({
    multiple: false,
    directory: true
  });

  if (file) {
    directory = file;
  }
}

$effect(() => {
  if (directory.length > 0) {
    valid = true;
  } else {
    valid = false;
  }
});

let shouldUseDefaultLocation: boolean = $state(true);
</script>

<h1 class="text-center text-3xl font-semibold">Select a location for your vaults.</h1>
<div class="flex w-full max-w-xl flex-col space-y-2 py-4">
  <div class="flex items-center space-x-2">
    <input type="checkbox" id="defaultLocation" bind:checked={shouldUseDefaultLocation} />
    <label for="defaultLocation">Use the default location for my vaults</label>
  </div>
  <div class="flex space-x-2">
    <input class="min-w-0 flex-1" disabled={shouldUseDefaultLocation} value={directory} />

    <button
      class="text-nowrap rounded-lg bg-blue-500 px-4 py-2 text-white"
      onclick={openFile}
      disabled={shouldUseDefaultLocation}>Browse Files</button
    >
  </div>
</div>
