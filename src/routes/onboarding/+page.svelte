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

<div class="flex h-full flex-col py-12 px-10 bg-stone-100 overflow-x-hidden items-center w-full">
  <h1 class="text-3xl font-semibold mb-8 text-center">Select a location for your vaults.</h1>
  <div class="flex flex-col max-w-3xl w-full justify-center">
    <div class="space-y-4 w-full">
      <div class="flex items-center space-x-2">
        <input type="checkbox" id="defaultLocation" bind:checked={shouldUseDefaultLocation} />
        <label for="defaultLocation">Use the default location for my vaults</label>
      </div>
      <div class="flex space-x-2">
        <input class="flex-1 min-w-0" disabled={shouldUseDefaultLocation}/>

        <button class="bg-blue-500 text-white py-2 px-4 rounded-lg text-nowrap" onclick={openFile} disabled={shouldUseDefaultLocation}>Browse Files</button>
      </div>
    </div>
  </div>
</div>
