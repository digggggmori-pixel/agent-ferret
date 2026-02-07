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
  {#if page === 'home'}
    <Home onstart={goToScan} />
  {:else if page === 'scanning'}
    <Scanning oncomplete={onScanComplete} />
  {:else if page === 'results'}
    <Results result={scanResult} onrescan={goHome} />
  {/if}
</div>
