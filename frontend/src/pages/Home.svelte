<script>
  import { GetVersion, IsAdmin, GetHostInfo } from '../../wailsjs/go/main/App.js'
  import { onMount } from 'svelte'
  import FerretMascot from '../components/FerretMascot.svelte'

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

  const categories = ['PROC', 'NET', 'SVC', 'REG', 'SIGMA', 'LOGS']
</script>

<div class="home-page">
  <!-- Mascot -->
  <div class="mascot-area">
    <FerretMascot pose="idle" scale={6} speech="Ready to search!" />
    <div class="platform-glow"></div>
  </div>

  <!-- Title -->
  <div class="title-area">
    <h1 class="pixel-font neon-text-cyan" style="font-size:20px; margin-bottom:8px;">FERRET</h1>
    <p class="pixel-font neon-text-magenta" style="font-size:8px; margin-bottom:4px;">by BRIQA</p>
    <p class="pixel-font" style="font-size:7px; color:#555;">SECURITY SCANNER</p>
  </div>

  <!-- System Info -->
  {#if hostInfo}
    <div class="system-info mono-font">
      <span style="color:#00ffff;">{hostInfo.hostname}</span>
      <span style="color:#333;"> | </span>
      <span style="color:#888;">{hostInfo.os_version}</span>
      <span style="color:#333;"> | </span>
      <span style="color:#888;">{hostInfo.ip_addresses?.[0] || ''}</span>
    </div>
  {/if}

  <!-- Start Button -->
  <button onclick={handleStart} disabled={loading} class="start-btn pixel-font">
    {#if loading}
      <span class="animate-pulse-text">LOADING...</span>
    {:else}
      [ START SCAN ]
    {/if}
  </button>

  <!-- Admin Notice -->
  {#if !isAdmin}
    <div class="admin-notice mono-font">
      <span style="color:#ff8800;">!</span> Run as administrator for better results
    </div>
  {/if}

  <!-- Bottom Categories -->
  <div class="categories">
    {#each categories as cat}
      <span class="cat-badge pixel-font">{cat}</span>
    {/each}
  </div>

  <p class="mono-font" style="color:#333; font-size:10px; margin-top:8px;">v{version}</p>
</div>

<style>
  .home-page {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 24px;
    gap: 4px;
  }
  .mascot-area {
    position: relative;
    margin-bottom: 16px;
  }
  .platform-glow {
    position: absolute;
    bottom: -8px;
    left: 50%;
    transform: translateX(-50%);
    width: 120px;
    height: 16px;
    background: radial-gradient(ellipse, rgba(0, 255, 255, 0.2) 0%, transparent 70%);
    border-radius: 50%;
  }
  .title-area {
    text-align: center;
    margin-bottom: 12px;
  }
  .system-info {
    font-size: 11px;
    padding: 6px 14px;
    background: #0d0d1a;
    border: 1px solid #1a1a3a;
    margin-bottom: 16px;
    text-align: center;
  }
  .start-btn {
    font-size: 12px;
    color: #00ffff;
    background: transparent;
    border: 2px solid #00ffff;
    padding: 14px 40px;
    cursor: pointer;
    transition: all 0.3s;
    text-shadow: 0 0 10px rgba(0, 255, 255, 0.5);
    box-shadow: 0 0 15px rgba(0, 255, 255, 0.1);
    margin-bottom: 12px;
  }
  .start-btn:hover:not(:disabled) {
    background: rgba(0, 255, 255, 0.05);
    box-shadow: 0 0 25px rgba(0, 255, 255, 0.3);
  }
  .start-btn:disabled {
    color: #555;
    border-color: #333;
    text-shadow: none;
    box-shadow: none;
    cursor: default;
  }
  .admin-notice {
    font-size: 10px;
    color: #ff880088;
    padding: 6px 12px;
    border: 1px solid #ff880030;
    background: rgba(255, 136, 0, 0.03);
    margin-bottom: 12px;
  }
  .categories {
    display: flex;
    gap: 8px;
    margin-top: auto;
    padding-top: 16px;
  }
  .cat-badge {
    font-size: 7px;
    color: #333;
    padding: 4px 8px;
    border: 1px solid #1a1a3a;
    background: #0a0a15;
  }
</style>
