<script lang="ts">
import { invoke } from '@tauri-apps/api/core';
import OnboardingEnterMasterPassword from './OnboardingEnterMasterPassword.svelte';
import OnboardingSelectDirectory from './OnboardingSelectDirectory.svelte';

const steps = ['select-directory', 'enter-master-password'];

type Steps = typeof steps;
type Step = Steps[number];

let isStepValid: boolean = $state(true);

let vaultDirectory: string = $state('~/vaults');
let masterPassword: string = $state('');

let activeStepIndex: number = $state(0);
let activeStep: Step = $derived(steps[activeStepIndex]);

let hasPreviousStep: boolean = $derived(activeStepIndex - 1 >= 0);
let hasNextStep: boolean = $derived(activeStepIndex + 1 < steps.length);

let showFinishButton: boolean = $derived(activeStepIndex === steps.length - 1 && isStepValid);

function previousStep() {
  activeStepIndex = Math.max(activeStepIndex - 1, 0);
}

function nextStep() {
  activeStepIndex = Math.min(activeStepIndex + 1, steps.length - 1);
}

async function initStore() {
  await invoke('init_store', { path: vaultDirectory });
}
</script>

<div
  class="flex h-full w-full flex-col items-center justify-between overflow-x-hidden bg-stone-100 px-10 pb-6 pt-12"
>
  {#if activeStep === 'select-directory'}
    <OnboardingSelectDirectory bind:directory={vaultDirectory} bind:valid={isStepValid} />
  {:else if activeStep === 'enter-master-password'}
    <OnboardingEnterMasterPassword bind:password={masterPassword} bind:valid={isStepValid} />
  {/if}
  <div class="flex w-full space-x-1">
    <div class="w-1/2">
      {#if hasPreviousStep}
        <button class="w-full bg-blue-500 px-4 py-2 text-white" onclick={previousStep}>
          Back
        </button>
      {/if}
    </div>
    <div class="w-1/2">
      {#if showFinishButton}
        <button class="w-full bg-blue-500 px-4 py-2 text-white" onclick={initStore}>
          Finish
        </button>
      {:else if hasNextStep}
        <button
          class="w-full bg-blue-500 px-4 py-2 text-white"
          disabled={!isStepValid}
          onclick={nextStep}
        >
          Next
        </button>
      {/if}
    </div>
  </div>
</div>
