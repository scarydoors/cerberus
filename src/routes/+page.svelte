<script lang="ts">
import VaultItem from '$lib/components/VaultItem.svelte';

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

<div class="flex h-screen text-neutral-100">

</div>
