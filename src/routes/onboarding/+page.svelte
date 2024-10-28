<script lang="ts">
import { open } from '@tauri-apps/plugin-dialog';

async function openFile() {
  const file = await open({
    multiple: false,
    directory: true,
  });
}

let shouldUseDefaultLocation: boolean = $state(true);

</script>

<div class="flex h-full flex-col pt-12 pb-6 px-10 bg-stone-100 overflow-x-hidden items-center w-full justify-between">
  <h1 class="text-3xl font-semibold text-center">Select a location for your vaults.</h1>
  <div class="flex flex-col max-w-xl w-full space-y-2 py-4">
      <div class="flex items-center space-x-2">
        <input type="checkbox" id="defaultLocation" bind:checked={shouldUseDefaultLocation} />
        <label for="defaultLocation">Use the default location for my vaults</label>
      </div>
      <div class="flex space-x-2">
        <input class="flex-1 min-w-0" disabled={shouldUseDefaultLocation}/>

        <button class="bg-blue-500 text-white py-2 px-4 rounded-lg text-nowrap" onclick={openFile} disabled={shouldUseDefaultLocation}>Browse Files</button>
      </div>
  </div>
  <div class="flex space-x-1 w-full">
    <button class="flex-1 bg-blue-500 text-white py-2 px-4">
      Back
    </button>
    <button class="flex-1 bg-blue-500 text-white py-2 px-4">
      Next
    </button>
  </div>
</div>
