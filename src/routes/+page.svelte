<script lang="ts">
import VaultItem from '$lib/components/VaultItem.svelte';
import { Button } from 'bits-ui';
import IconMagnifyingGlass from '~icons/ph/magnifying-glass-bold';
import IconPlus from '~icons/ph/plus-bold';
import IconArrowLeft from '~icons/ph/arrow-left-bold';
import IconArrowRight from '~icons/ph/arrow-right-bold';
import CaretLeft from '~icons/ph/caret-left-bold';
import CaretRight from '~icons/ph/caret-right-bold';

const vaultItems = [
  { id: 1, name: 'Google', site: 'www.google.com' },
  { id: 2, name: 'Facebook', site: 'www.facebook.com' },
  { id: 3, name: 'Twitter', site: 'www.twitter.com' },
  { id: 4, name: 'LinkedIn', site: 'www.linkedin.com' },
  { id: 5, name: 'GitHub', site: 'www.github.com' },
  { id: 6, name: 'Reddit', site: 'www.reddit.com' },
  { id: 7, name: 'Instagram', site: 'www.instagram.com' },
  { id: 8, name: 'Snapchat', site: 'www.snapchat.com' },
  { id: 9, name: 'Pinterest', site: 'www.pinterest.com' },
  { id: 10, name: 'YouTube', site: 'www.youtube.com' },
  { id: 11, name: 'TikTok', site: 'www.tiktok.com' },
  { id: 12, name: 'WhatsApp', site: 'www.whatsapp.com' },
  { id: 13, name: 'Telegram', site: 'www.telegram.org' },
  { id: 14, name: 'Discord', site: 'www.discord.com' },
  { id: 15, name: 'Slack', site: 'www.slack.com' },
  { id: 16, name: 'Zoom', site: 'www.zoom.us' },
  { id: 17, name: 'Skype', site: 'www.skype.com' },
  { id: 18, name: 'Viber', site: 'www.viber.com' },
  { id: 19, name: 'WeChat', site: 'www.wechat.com' },
  { id: 20, name: 'Signal', site: 'www.signal.org' }
];

let selectedVaultItemId = $state<number | null>(null);
</script>

<header data-tauri-drag-region class="h-13 bg-neutral-800 flex items-center py-2.5 w-full justify-center gap-3">
  <div class="flex items-center h-full">
    <Button.Root class="rounded-md text-neutral-300 cursor-pointer active:bg-primary-400/30 hover:bg-primary-500/30 size-8 flex items-center justify-center">
      <CaretLeft class="size-4" />
    </Button.Root>
    <Button.Root class="rounded-md text-neutral-300 cursor-pointer active:bg-primary-400/30 hover:bg-primary-500/30 size-8 flex items-center justify-center">
      <CaretRight class="size-4" />
    </Button.Root>
  </div>
  <div class="relative">
    <div class="absolute inset-y-0 flex items-center pointer-events-none pl-2 text-neutral-400">
      <IconMagnifyingGlass class="size-5" />
    </div>
    <input placeholder="Search for items" class="pl-9 h-8 w-128 placeholder:text-neutral-400 rounded-lg bg-neutral-900 border border-neutral-700 text-sm focus:ring-3 focus:ring-primary-500/30" />
  </div>
  <Button.Root class="flex items-center bg-primary-500 gap-2 h-8 rounded-lg pl-2 pr-2 text-sm border border-primary-400">
    <IconPlus class="size-4"/>
    New Item
  </Button.Root>
</header>
<div class="flex h-full">
  <div class="w-64 bg-neutral-800 h-full border-t border-r border-neutral-700">
  </div>
  <div class="w-64 bg-neutral-800 h-full border-t border-t-neutral-700">
  </div>
</div>
