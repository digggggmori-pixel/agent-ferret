<script>
  import { ExportJSON, OpenBRIQA } from '../../wailsjs/go/main/App.js'
  import DetectionCard from '../components/DetectionCard.svelte'
  import SeverityBadge from '../components/SeverityBadge.svelte'
  import ThreatScore from '../components/ThreatScore.svelte'
  import FerretMascot from '../components/FerretMascot.svelte'

  let { result, onrescan } = $props()

  let exportPath = $state('')
  let activeFilter = $state('all')
  let expandedId = $state(null)

  const summary = $derived(result?.summary?.detections || { critical: 0, high: 0, medium: 0, low: 0 })
  const totalDetections = $derived(summary.critical + summary.high + summary.medium + summary.low)

  const filteredDetections = $derived(() => {
    if (!result?.detections) return []
    if (activeFilter === 'all') return result.detections
    return result.detections.filter(d => d.severity === activeFilter)
  })

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  const sortedDetections = $derived(() => {
    return [...filteredDetections()].sort((a, b) =>
      (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
    )
  })

  async function handleExport() {
    try {
      exportPath = await ExportJSON()
    } catch (e) {
      console.error('Export failed:', e)
    }
  }

  function toggleExpand(id) {
    expandedId = expandedId === id ? null : id
  }

  function formatDuration(ms) {
    return (ms / 1000).toFixed(1) + 's'
  }

  const sevConfig = [
    { key: 'critical', label: 'CRIT', color: '#ff0040' },
    { key: 'high', label: 'HIGH', color: '#ff8800' },
    { key: 'medium', label: 'MED', color: '#ffb800' },
    { key: 'low', label: 'LOW', color: '#00ffff' },
  ]
</script>

<div class="results-page">
  <!-- Header -->
  <div class="results-header">
    <div class="header-left">
      <h2 class="pixel-font neon-text-cyan" style="font-size:10px;">SCAN RESULTS</h2>
      <p class="mono-font" style="font-size:10px; color:#555; margin-top:2px;">
        {result?.host?.hostname || 'Unknown'} &middot; {formatDuration(result?.scan_duration_ms || 0)}
      </p>
    </div>
    <div class="header-buttons">
      <button onclick={handleExport} class="retro-btn mono-font">EXPORT</button>
      <button onclick={onrescan} class="retro-btn primary mono-font">RESCAN</button>
    </div>
  </div>
  {#if exportPath}
    <p class="mono-font neon-text-green" style="font-size:10px; padding:0 16px;">Saved: {exportPath}</p>
  {/if}

  <!-- Threat Score + Summary -->
  <div class="score-section animate-fade-in-up">
    <ThreatScore {summary} />
    <div class="sev-grid">
      {#each sevConfig as sev}
        <button
          onclick={() => activeFilter = activeFilter === sev.key ? 'all' : sev.key}
          class="sev-card"
          class:active={activeFilter === sev.key}
          style="--sev-color:{sev.color};"
        >
          <span class="sev-count pixel-font" style="color:{sev.color}; text-shadow: 0 0 10px {sev.color}40;">
            {summary[sev.key]}
          </span>
          <span class="sev-label pixel-font">{sev.label}</span>
        </button>
      {/each}
    </div>
  </div>

  <!-- Filter indicator -->
  {#if activeFilter !== 'all'}
    <div class="filter-bar">
      <SeverityBadge severity={activeFilter} />
      <span class="mono-font" style="font-size:10px; color:#555;">{sortedDetections().length} showing</span>
      <button onclick={() => activeFilter = 'all'} class="mono-font filter-clear">Show all</button>
    </div>
  {/if}

  <!-- Detection List -->
  <div class="detection-list">
    {#if sortedDetections().length === 0}
      <div class="no-threats animate-fade-in-up">
        <FerretMascot pose="happy" scale={5} speech="All clear!" />
        <p class="pixel-font neon-text-green" style="font-size:9px; margin-top:16px;">NO THREATS DETECTED</p>
        <p class="mono-font" style="color:#555; font-size:11px; margin-top:4px;">Your system appears safe</p>
      </div>
    {:else}
      {#each sortedDetections() as detection, i (detection.id)}
        <div class="animate-fade-in-up" style="animation-delay: {Math.min(i * 0.05, 0.3)}s">
          <DetectionCard
            {detection}
            expanded={expandedId === detection.id}
            ontoggle={() => toggleExpand(detection.id)}
          />
        </div>
      {/each}
    {/if}
  </div>

  <!-- CTA Banner -->
  {#if totalDetections > 0}
    <div class="cta-banner">
      <div class="cta-content">
        <FerretMascot pose="sniff" scale={3} />
        <div class="cta-text">
          <p class="pixel-font" style="font-size:8px; color:#ff00ff;">GET AI ANALYSIS</p>
          <p class="mono-font" style="font-size:10px; color:#888; margin-top:3px;">Understand threats and get remediation steps</p>
        </div>
      </div>
      <button onclick={() => OpenBRIQA()} class="cta-btn pixel-font">
        [ ANALYZE WITH BRIQA AI ]
      </button>
    </div>
  {/if}
</div>

<style>
  .results-page {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .results-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    background: #0a0a15;
    border-bottom: 2px solid #1a1a3a;
  }
  .header-buttons {
    display: flex;
    gap: 6px;
  }
  .retro-btn {
    font-size: 9px;
    padding: 5px 12px;
    border: 1px solid #1a1a3a;
    background: #0d0d1a;
    color: #888;
    cursor: pointer;
    transition: all 0.2s;
  }
  .retro-btn:hover {
    border-color: #00ffff;
    color: #00ffff;
  }
  .retro-btn.primary {
    border-color: #00ffff40;
    color: #00ffff;
  }
  .retro-btn.primary:hover {
    background: rgba(0, 255, 255, 0.05);
    border-color: #00ffff;
  }

  .score-section {
    display: flex;
    align-items: center;
    gap: 20px;
    padding: 16px;
  }
  .sev-grid {
    flex: 1;
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 6px;
  }
  .sev-card {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    padding: 10px 4px;
    background: #0a0a1a;
    border: 2px solid #1a1a3a;
    cursor: pointer;
    transition: all 0.2s;
  }
  .sev-card.active {
    border-color: var(--sev-color);
    box-shadow: 0 0 10px color-mix(in srgb, var(--sev-color) 20%, transparent);
    background: color-mix(in srgb, var(--sev-color) 3%, #0a0a1a);
  }
  .sev-card:hover {
    border-color: var(--sev-color);
  }
  .sev-count {
    font-size: 18px;
  }
  .sev-label {
    font-size: 6px;
    color: #555;
  }

  .filter-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 16px;
  }
  .filter-clear {
    margin-left: auto;
    font-size: 10px;
    color: #00ffff;
    background: none;
    border: none;
    cursor: pointer;
    padding: 0;
  }
  .filter-clear:hover { text-decoration: underline; }

  .detection-list {
    flex: 1;
    overflow-y: auto;
    padding: 8px 16px 16px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .no-threats {
    text-align: center;
    padding: 40px 0;
    display: flex;
    flex-direction: column;
    align-items: center;
  }

  .cta-banner {
    padding: 12px 16px;
    background: #0a0a1a;
    border-top: 2px solid #1a1a3a;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }
  .cta-content {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .cta-btn {
    font-size: 8px;
    padding: 10px 16px;
    border: 2px solid #ff00ff;
    background: transparent;
    color: #ff00ff;
    cursor: pointer;
    transition: all 0.3s;
    text-shadow: 0 0 10px rgba(255, 0, 255, 0.4);
    box-shadow: 0 0 12px rgba(255, 0, 255, 0.1);
    white-space: nowrap;
  }
  .cta-btn:hover {
    background: rgba(255, 0, 255, 0.05);
    box-shadow: 0 0 20px rgba(255, 0, 255, 0.3);
  }
</style>
