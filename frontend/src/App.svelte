<script>
  import './app.css'
  import Home from './pages/Home.svelte'
  import Scanning from './pages/Scanning.svelte'
  import Results from './pages/Results.svelte'
  import { WindowMinimise, WindowMaximise, Quit } from '../wailsjs/runtime/runtime.js'

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

<div class="h-full flex flex-col" style="background:#080810;">
  <!-- Retro Title Bar -->
  <header class="title-bar" style="-webkit-app-region: drag;">
    <div class="title-left">
      <span class="pixel-font neon-text-cyan" style="font-size:9px;">&#9632; Ferret v1.0.0</span>
    </div>
    {#if page !== 'home'}
      <span class="pixel-font" style="font-size:7px; color:#555;">
        {page === 'scanning' ? 'SCANNING...' : 'RESULTS'}
      </span>
    {/if}
    <div class="title-buttons" style="-webkit-app-region: no-drag;">
      <button class="title-btn" onclick={() => WindowMinimise()}>_</button>
      <button class="title-btn" onclick={() => WindowMaximise()}>&#9633;</button>
      <button class="title-btn close" onclick={() => Quit()}>X</button>
    </div>
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

  <!-- Status Bar -->
  <footer class="status-bar">
    <div class="status-left">
      <span class="status-dot"></span>
      <span class="mono-font" style="font-size:10px;">
        {page === 'scanning' ? 'SCANNING' : 'READY'}
      </span>
    </div>
    <div class="status-right mono-font">
      <span style="color:#555;">FERRET v1.0.0</span>
      <span style="color:#333; margin:0 6px;">|</span>
      <span style="color:#555;">BRIQA</span>
    </div>
  </footer>
</div>

<style>
  .title-bar {
    background: linear-gradient(90deg, #0a0a1e, #12122a);
    border-bottom: 2px solid #1a1a3a;
    padding: 7px 12px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    user-select: none;
    flex-shrink: 0;
  }
  .title-left {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .title-buttons {
    display: flex;
    gap: 4px;
  }
  .title-btn {
    width: 16px;
    height: 16px;
    border: 2px solid #1a1a3a;
    background: #0d0d1a;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: var(--font-pixel);
    font-size: 6px;
    color: #555;
    padding: 0;
    transition: all 0.2s;
  }
  .title-btn:hover { border-color: #00ffff; color: #00ffff; }
  .title-btn.close:hover { border-color: #ff0040; color: #ff0040; }

  .status-bar {
    background: #0a0a15;
    border-top: 2px solid #1a1a3a;
    padding: 5px 12px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-shrink: 0;
  }
  .status-left {
    display: flex;
    align-items: center;
    color: #00ff41;
    font-size: 10px;
  }
  .status-dot {
    width: 8px;
    height: 8px;
    background: #00ff41;
    box-shadow: 0 0 6px #00ff41;
    display: inline-block;
    margin-right: 6px;
  }
  .status-right {
    font-size: 10px;
  }
</style>
