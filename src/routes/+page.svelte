<script lang="ts">
import VaultItem from '$lib/components/VaultItem.svelte';
import { Button } from 'bits-ui';
import IconMagnifyingGlass from '~icons/ph/magnifying-glass-bold';
import IconPlus from '~icons/ph/plus-bold';
import IconCaretLeft from '~icons/ph/caret-left-bold';
import IconCaretRight from '~icons/ph/caret-right-bold';
import IconCardsThree from '~icons/ph/cards-three-fill';
import IconCaretDown from '~icons/ph/caret-down-bold';
import IconVault from '~icons/ph/vault-fill';
import IconDotsThree from '~icons/ph/dots-three-outline-fill';
import IconNotePencil from '~icons/ph/note-pencil-fill';

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
    <Button.Root class="rounded-lg text-neutral-300 cursor-pointer active:bg-primary-400/30 hover:bg-primary-500/30 size-8 flex items-center justify-center">
      <IconCaretLeft class="size-4" />
    </Button.Root>
    <Button.Root class="rounded-lg text-neutral-300 cursor-pointer active:bg-primary-400/30 hover:bg-primary-500/30 size-8 flex items-center justify-center">
      <IconCaretRight class="size-4" />
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
    <div class="p-2">
      <Button.Root class="p-2 flex items-center gap-2.5 text-sm font-medium rounded-lg hover:bg-primary-500/30 w-full mb-3">
        <IconCardsThree class="size-5 text-neutral-300"/>
        All Items
      </Button.Root>
      <div class="flex items-center gap-1">
      <Button.Root class="p-2 flex items-center gap-2.5 text-sm font-medium rounded-lg hover:bg-primary-500/30 flex-1">
        <IconCaretDown class="size-5 text-neutral-300"/>
        Vaults
      </Button.Root>
      <Button.Root class="rounded-lg text-neutral-300 cursor-pointer active:bg-primary-400/30 hover:bg-primary-500/30 size-7 flex items-center justify-center">
        <IconPlus class="size-4" />
      </Button.Root>
      </div>
      <Button.Root class="p-2 flex items-center gap-2.5 text-sm font-medium rounded-lg hover:bg-primary-500/30 w-full">
        <IconVault class="size-5 text-neutral-300"/>
        My Stuff
      </Button.Root>
    </div>
  </div>
  <div class="w-64 bg-neutral-800 h-full border-t border-t-neutral-700">
    <div class="p-2">
      <div class="flex items-center px-2 h-13 gap-4 hover:bg-primary-500/30 rounded-lg">
        <div class="rounded-lg bg-neutral-300 size-8">
        </div>
        <div>
          <h1 class="text-neutral-50 font-semibold">Google</h1>
          <p class="text-neutral-300 text-xs">john.doe@gmail.com</p>
        </div>
      </div>
    </div>
  </div>
  <div class="flex-1 pt-12">
    <div class="mx-auto max-w-5xl px-4">
      <div class="flex items-center justify-between px-4 mb-6">
        <div class="flex items-center gap-4 text-2xl font-bold">
          <div class="rounded-lg bg-neutral-300 size-12">
          </div>
          Google
        </div>
        <div class="flex items-center gap-1">
          <Button.Root class="rounded-lg text-neutral-300 cursor-pointer active:bg-primary-400/30 hover:bg-primary-500/30 flex items-center text-sm px-2 h-8 gap-2">
            <IconVault class="size-5" />
            My Stuff
          </Button.Root>
          <Button.Root class="rounded-lg text-neutral-300 cursor-pointer active:bg-primary-400/30 hover:bg-primary-500/30 size-8 flex items-center justify-center">
            <IconNotePencil class="size-5" />
          </Button.Root>
          <Button.Root class="rounded-lg text-neutral-300 cursor-pointer active:bg-primary-400/30 hover:bg-primary-500/30 size-8 flex items-center justify-center">
            <IconDotsThree class="size-5" />
          </Button.Root>
        </div>
      </div>
      <div class="mb-5">
        <div class="bg-neutral-800 border-neutral-700 w-full rounded-t-2xl p-4 flex flex-col gap-2.5 border-x border-t">
          <div class="text-xs font-light text-neutral-300">
            Username
          </div>
          <div class="text-neutral-50 text-sm">
            john.doe@gmail.com
          </div>
        </div>
        <div class="bg-neutral-800 border-neutral-700 w-full rounded-b-2xl p-4 flex flex-col gap-2.5 border shadow-md">
          <div class="text-xs font-light text-neutral-300">
            Password
          </div>
          <div class="text-neutral-50 text-sm">
            ********
          </div>
        </div>
      </div>
      <div class="flex flex-col w-full items-center text-neutral-400 text-xs font-light gap-1">
        <div>Updated at 2025-01-01 12:00:00</div>
        <div>Created at 2025-01-01 12:00:00</div>
      </div>
    </div>
  </div>
</div>
