<script>
  import './app.css'
  import Home from './pages/Home.svelte'
  import Scanning from './pages/Scanning.svelte'
  import Results from './pages/Results.svelte'

  let page = $state('home')
  let scanResult = $state(null)

  function goToScan() {
    page = 'scanning'
  }

  function onScanComplete(result) {
    scanResult = result
    page = 'results'
  }

  function goHome() {
    scanResult = null
    page = 'home'
  }
</script>

<div class="h-full flex flex-col bg-(--color-bg-primary)">
  <!-- Header -->
  <header class="flex items-center justify-between px-5 py-2.5 bg-(--color-bg-secondary)/80 border-b border-slate-800/50" style="backdrop-filter: blur(8px); -webkit-app-region: drag;">
    <div class="flex items-center gap-2">
      <svg class="w-5 h-5 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
      <span class="text-sm font-semibold text-white tracking-wide">Ferret</span>
      <span class="text-[10px] text-slate-500 ml-1">by BRIQA</span>
    </div>
    {#if page !== 'home'}
      <span class="text-[10px] text-slate-500 uppercase tracking-widest">
        {page === 'scanning' ? 'Scanning' : 'Results'}
      </span>
    {/if}
  </header>

  <!-- Page Content -->
  {#key page}
    <div class="flex-1 flex flex-col overflow-hidden animate-fade-in">
      {#if page === 'home'}
        <Home onstart={goToScan} />
      {:else if page === 'scanning'}
        <Scanning oncomplete={onScanComplete} />
      {:else if page === 'results'}
        <Results result={scanResult} onrescan={goHome} />
      {/if}
    </div>
  {/key}
</div>
