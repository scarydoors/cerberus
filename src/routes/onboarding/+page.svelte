<script lang="ts">
  import OnboardingEnterMasterPassword from "./OnboardingEnterMasterPassword.svelte";
import OnboardingSelectDirectory from "./OnboardingSelectDirectory.svelte";

  const steps = [
    'select-directory',
    'enter-master-password',
  ];

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
  };

  function nextStep() {
    activeStepIndex = Math.min(activeStepIndex + 1, steps.length - 1);
  }

</script>

<div class="flex h-full flex-col pt-12 pb-6 px-10 bg-stone-100 overflow-x-hidden items-center w-full justify-between">
  {#if activeStep === 'select-directory'}
    <OnboardingSelectDirectory bind:directory={vaultDirectory} bind:valid={isStepValid} />
  {:else if activeStep === 'enter-master-password'}
    <OnboardingEnterMasterPassword bind:password={masterPassword} bind:valid={isStepValid} />
  {/if}
  <div class="flex space-x-1 w-full">
    <div class="w-1/2">
    {#if hasPreviousStep}
      <button class="bg-blue-500 text-white py-2 px-4 w-full" onclick={previousStep}>
        Back
      </button>
    {/if}
      </div>
    <div class="w-1/2">
      {#if showFinishButton}
        <button class="bg-blue-500 text-white py-2 px-4 w-full">
          Finish
        </button>
      {:else if hasNextStep}
        <button class="bg-blue-500 text-white py-2 px-4 w-full" disabled={!isStepValid} onclick={nextStep}>
          Next
        </button>
      {/if}
      </div>
  </div>
</div>
