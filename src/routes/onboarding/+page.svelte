<script lang="ts">
  let masterPassword = $state(undefined);
</script>

<div class="flex h-full flex-col items-center justify-center">
  <h1>Enter a new master password</h1>
  <input bind:value={masterPassword} />
</div>
