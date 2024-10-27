<script lang="ts">
let masterPassword = $state(undefined);
</script>

<div class="flex justify-center flex-col items-center h-full">
	<h1> Enter a new master password </h1>
	<input bind:value={masterPassword}/>
</div>
