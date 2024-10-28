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

<h1 class="text-3xl font-semibold text-center">Create your master password.</h1>
<div class="flex flex-col max-w-xl w-full space-y-2 py-4">
  <input bind:value={password} type="password"/>
</div>
