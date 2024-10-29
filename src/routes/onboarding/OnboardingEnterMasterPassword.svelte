<script lang="ts">
import { zxcvbn } from '@zxcvbn-ts/core';

type Props = {
  password: string;
  valid: boolean;
};

let { password = $bindable(), valid = $bindable() }: Props = $props();

$effect(() => {
  if (password.length > 0) {
    valid = true;
  } else {
    valid = false;
  }

  console.log(zxcvbn(password));
});
</script>

<h1 class="text-center text-3xl font-semibold">Create your master password.</h1>
<div class="flex w-full max-w-xl flex-col space-y-2 py-4">
  <input bind:value={password} type="password" />
</div>
