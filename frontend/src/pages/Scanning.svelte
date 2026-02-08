<script>
  import { StartScan } from '../../wailsjs/go/main/App.js'
  import { EventsOn, EventsOff } from '../../wailsjs/runtime/runtime.js'
  import { onMount, onDestroy } from 'svelte'
  import FerretMascot from '../components/FerretMascot.svelte'
  import PixelProgressBar from '../components/PixelProgressBar.svelte'
  import ScanScene from '../components/ScanScene.svelte'

  let { oncomplete } = $props()

  let progress = $state({
    step: 0, total: 8, stepName: 'Initializing...', percent: 0, detail: '', done: false
  })
  let elapsed = $state(0)
  let detectionCount = $state(0)
  let timer = null

  onMount(async () => {
    timer = setInterval(() => { elapsed += 1 }, 1000)

    EventsOn('scan:progress', (data) => {
      progress = data

      if (data.step === 5 && data.detail) {
        const match = data.detail.match(/(\d+)/)
        if (match) detectionCount = parseInt(match[1])
      }
    })

    try {
      const result = await StartScan()
      clearInterval(timer)
      setTimeout(() => oncomplete(result), 800)
    } catch (err) {
      clearInterval(timer)
      console.error('Scan failed:', err)
    }
  })

  onDestroy(() => {
    clearInterval(timer)
    EventsOff('scan:progress')
  })

  function formatTime(seconds) {
    const m = Math.floor(seconds / 60)
    const s = seconds % 60
    return m > 0 ? `${m}m ${s}s` : `${s}s`
  }
</script>

<div class="scanning-page">
  <!-- Header -->
  <div class="scan-header">
    <h2 class="pixel-font neon-text-cyan" style="font-size:11px;">SCANNING</h2>
    <p class="mono-font" style="font-size:10px; color:#555;">Elapsed: {formatTime(elapsed)}</p>
  </div>

  <!-- Progress Bar (block style) -->
  <div class="progress-section">
    <div class="progress-info mono-font">
      <span class="neon-text-cyan" style="font-size:11px;">{progress.stepName}</span>
      <span style="color:#555; font-size:11px;">{progress.step}/{progress.total}</span>
    </div>
    <PixelProgressBar total={progress.total} filled={progress.step} warn={detectionCount > 0} />
  </div>

  <!-- Scan Scene -->
  <div class="scene-area">
    <ScanScene currentStep={progress.step} {detectionCount} />
  </div>

  <!-- Status Detail -->
  {#if progress.detail}
    <div class="status-detail mono-font">
      <span class="animate-blink" style="color:#00ffff;">&#x25B6;</span>
      <span style="color:#888; font-size:11px;">{progress.detail}</span>
    </div>
  {/if}

  <!-- Detection counter -->
  {#if detectionCount > 0}
    <div class="detection-counter">
      <span class="pixel-font" style="font-size:7px; color:#ff8800;">
        ! {detectionCount} DETECTIONS FOUND
      </span>
    </div>
  {/if}

  <!-- Complete -->
  {#if progress.done}
    <div class="scan-complete animate-fade-in">
      <FerretMascot pose="happy" scale={4} speech="All clear!" />
      <p class="pixel-font neon-text-green" style="font-size:9px; margin-top:12px;">SCAN COMPLETE!</p>
    </div>
  {/if}
</div>

<style>
  .scanning-page {
    flex: 1;
    display: flex;
    flex-direction: column;
    padding: 16px 20px;
    gap: 12px;
    overflow-y: auto;
  }
  .scan-header {
    text-align: center;
  }
  .progress-section {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .progress-info {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .scene-area {
    flex: 1;
    min-height: 0;
  }
  .status-detail {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 10px;
    background: #0a0a15;
    border: 1px solid #1a1a3a;
  }
  .detection-counter {
    text-align: center;
    padding: 6px;
    border: 1px solid #ff880040;
    background: rgba(255, 136, 0, 0.03);
  }
  .scan-complete {
    text-align: center;
    padding: 16px 0 8px;
    display: flex;
    flex-direction: column;
    align-items: center;
  }
</style>
