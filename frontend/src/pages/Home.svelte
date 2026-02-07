<script>
  import { GetVersion, IsAdmin, GetHostInfo } from '../../wailsjs/go/main/App.js'
  import { onMount } from 'svelte'

  let { onstart } = $props()
  let version = $state('')
  let isAdmin = $state(false)
  let hostInfo = $state(null)
  let loading = $state(false)

  onMount(async () => {
    version = await GetVersion()
    isAdmin = await IsAdmin()
    hostInfo = await GetHostInfo()
  })

  async function handleStart() {
    loading = true
    onstart()
  }

  const scanCategories = [
    { icon: 'M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z', label: 'Processes' },
    { icon: 'M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9', label: 'Network' },
    { icon: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01', label: 'Services' },
    { icon: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z', label: 'Registry' },
    { icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2', label: 'Event Logs' },
    { icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z', label: 'Sigma Rules' },
  ]
</script>

<div class="flex-1 flex flex-col items-center justify-center p-8 animate-fade-in-up">
  <!-- Logo -->
  <div class="mb-6 text-center">
    <div class="w-20 h-20 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-cyan-900/40 to-blue-900/40 border border-cyan-700/30 flex items-center justify-center animate-pulse-glow">
      <svg class="w-11 h-11 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    </div>
    <h1 class="text-2xl font-bold text-white mb-1">Security Scanner</h1>
    <p class="text-xs text-cyan-400/80 font-medium tracking-widest uppercase">Powered by Ferret</p>
  </div>

  <!-- System Info Preview -->
  {#if hostInfo}
    <div class="mb-8 px-4 py-2.5 rounded-lg bg-(--color-bg-secondary) border border-slate-800/50 text-center">
      <p class="text-xs text-slate-400">
        <span class="text-slate-300 font-medium">{hostInfo.hostname}</span>
        <span class="mx-1.5 text-slate-600">|</span>
        {hostInfo.os_version}
        <span class="mx-1.5 text-slate-600">|</span>
        {hostInfo.ip_addresses?.[0] || ''}
      </p>
    </div>
  {/if}

  <!-- Description -->
  <p class="text-slate-400 text-center mb-8 max-w-sm text-sm leading-relaxed">
    Scan your PC for security threats.<br>
    Analyzes processes, network, services, registry, and event logs to detect suspicious activity.
  </p>

  <!-- Start Button -->
  <button
    onclick={handleStart}
    disabled={loading}
    class="group relative px-14 py-4 bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 disabled:from-cyan-800 disabled:to-cyan-700 text-white font-semibold text-base rounded-xl transition-all duration-300 shadow-lg shadow-cyan-900/40 hover:shadow-cyan-700/40 hover:scale-[1.02] cursor-pointer"
  >
    {#if loading}
      <span class="flex items-center gap-2">
        <svg class="animate-spin w-5 h-5" viewBox="0 0 24 24" fill="none">
          <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="3" class="opacity-25"/>
          <path d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" fill="currentColor" class="opacity-75"/>
        </svg>
        Preparing...
      </span>
    {:else}
      Start Scan
    {/if}
  </button>

  <!-- Admin Notice -->
  {#if !isAdmin}
    <div class="mt-5 px-4 py-2.5 bg-amber-900/20 border border-amber-800/30 rounded-lg max-w-sm">
      <p class="text-amber-300/80 text-xs text-center">
        Run as administrator for more accurate results.
      </p>
    </div>
  {/if}

  <!-- Scan Categories -->
  <div class="mt-auto pt-8 flex items-center gap-4 opacity-40">
    {#each scanCategories as cat}
      <div class="flex flex-col items-center gap-1">
        <svg class="w-4 h-4 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d={cat.icon} />
        </svg>
        <span class="text-[9px] text-slate-500">{cat.label}</span>
      </div>
    {/each}
  </div>

  <!-- Version -->
  <p class="mt-3 text-slate-700 text-[10px]">v{version}</p>
</div>
