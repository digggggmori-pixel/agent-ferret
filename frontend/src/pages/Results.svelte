<script>
  import { ExportJSON, OpenBRIQA } from '../../wailsjs/go/main/App.js'
  import DetectionCard from '../components/DetectionCard.svelte'
  import SeverityBadge from '../components/SeverityBadge.svelte'
  import ThreatScore from '../components/ThreatScore.svelte'

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
</script>

<div class="flex-1 flex flex-col overflow-hidden">
  <!-- Header -->
  <div class="px-6 py-3 bg-(--color-bg-secondary)/60 border-b border-slate-800/50" style="backdrop-filter: blur(8px);">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-base font-semibold text-white">Scan Results</h2>
        <p class="text-[11px] text-slate-500 mt-0.5">
          {result?.host?.hostname || 'Unknown'} &middot; {formatDuration(result?.scan_duration_ms || 0)} elapsed
        </p>
      </div>
      <div class="flex items-center gap-2">
        <button onclick={handleExport} class="px-3 py-1.5 text-[11px] bg-(--color-bg-card) hover:bg-(--color-bg-elevated) text-slate-300 rounded-lg transition cursor-pointer border border-slate-700/30">
          Export JSON
        </button>
        <button onclick={onrescan} class="px-3 py-1.5 text-[11px] bg-cyan-700 hover:bg-cyan-600 text-white rounded-lg transition cursor-pointer">
          Rescan
        </button>
      </div>
    </div>
    {#if exportPath}
      <p class="text-[11px] text-green-400 mt-1.5">Saved: {exportPath}</p>
    {/if}
  </div>

  <!-- Threat Score + Summary -->
  <div class="px-6 py-4 animate-fade-in-up">
    <div class="flex items-center gap-6">
      <ThreatScore {summary} />
      <div class="flex-1 grid grid-cols-4 gap-2">
        {#each [
          { key: 'critical', label: 'Critical', color: 'red' },
          { key: 'high', label: 'High', color: 'orange' },
          { key: 'medium', label: 'Medium', color: 'yellow' },
          { key: 'low', label: 'Low', color: 'green' },
        ] as sev}
          <button
            onclick={() => activeFilter = activeFilter === sev.key ? 'all' : sev.key}
            class="p-2.5 rounded-xl text-center transition cursor-pointer border
              {activeFilter === sev.key
                ? `bg-${sev.color}-900/30 border-${sev.color}-700/60`
                : 'glass hover:border-slate-600/50'}"
          >
            <p class="text-xl font-bold text-(--color-severity-{sev.key})">{summary[sev.key]}</p>
            <p class="text-[10px] text-slate-400 mt-0.5">{sev.label}</p>
          </button>
        {/each}
      </div>
    </div>
  </div>

  <!-- Filter indicator -->
  {#if activeFilter !== 'all'}
    <div class="px-6 pb-2 flex items-center gap-2 animate-fade-in">
      <SeverityBadge severity={activeFilter} />
      <span class="text-[11px] text-slate-400">{sortedDetections().length} showing</span>
      <button onclick={() => activeFilter = 'all'} class="text-[11px] text-cyan-400 hover:text-cyan-300 ml-auto cursor-pointer">
        Show all
      </button>
    </div>
  {/if}

  <!-- Detection List -->
  <div class="flex-1 overflow-y-auto px-6 pb-4 space-y-2">
    {#if sortedDetections().length === 0}
      <div class="text-center py-16 animate-fade-in-up">
        <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-green-900/20 border border-green-700/30 flex items-center justify-center">
          <svg class="w-8 h-8 text-green-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <p class="text-white font-medium text-sm">No threats detected</p>
        <p class="text-slate-500 text-xs mt-1">Your system appears safe</p>
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
    <div class="px-6 py-4 bg-gradient-to-r from-cyan-900/40 via-blue-900/40 to-purple-900/30 border-t border-cyan-800/20">
      <div class="flex items-center justify-between gap-4">
        <div class="flex-1">
          <p class="text-sm font-medium text-white">Get AI-powered threat analysis</p>
          <p class="text-[11px] text-slate-400 mt-0.5">Understand the real risk level and get actionable remediation steps</p>
        </div>
        <button onclick={() => OpenBRIQA()} class="flex items-center gap-1.5 px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white text-sm font-medium rounded-lg transition-all hover:scale-[1.02] whitespace-nowrap cursor-pointer shadow-lg shadow-cyan-900/30">
          Analyze with BRIQA
          <svg class="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M10.293 3.293a1 1 0 011.414 0l6 6a1 1 0 010 1.414l-6 6a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-4.293-4.293a1 1 0 010-1.414z" clip-rule="evenodd"/>
          </svg>
        </button>
      </div>
    </div>
  {/if}
</div>
