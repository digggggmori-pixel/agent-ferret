<script>
  import { ExportJSON, OpenBRIQA } from '../../wailsjs/go/main/App.js'
  import DetectionCard from '../components/DetectionCard.svelte'
  import SeverityBadge from '../components/SeverityBadge.svelte'

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
    return (ms / 1000).toFixed(1) + '초'
  }
</script>

<div class="flex-1 flex flex-col overflow-hidden">
  <!-- Header -->
  <div class="px-6 py-4 bg-(--color-bg-secondary) border-b border-slate-700/50">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-lg font-semibold text-white">점검 결과</h2>
        <p class="text-xs text-slate-400 mt-0.5">
          {result?.host?.hostname || 'Unknown'} | {formatDuration(result?.scan_duration_ms || 0)} 소요
        </p>
      </div>
      <div class="flex items-center gap-2">
        <button onclick={handleExport} class="px-3 py-1.5 text-xs bg-(--color-bg-card) hover:bg-slate-600 text-slate-300 rounded-lg transition cursor-pointer">
          JSON 저장
        </button>
        <button onclick={onrescan} class="px-3 py-1.5 text-xs bg-cyan-700 hover:bg-cyan-600 text-white rounded-lg transition cursor-pointer">
          다시 점검
        </button>
      </div>
    </div>
    {#if exportPath}
      <p class="text-xs text-green-400 mt-2">저장 완료: {exportPath}</p>
    {/if}
  </div>

  <!-- Summary Cards -->
  <div class="px-6 py-4">
    <div class="grid grid-cols-4 gap-3">
      <button onclick={() => activeFilter = activeFilter === 'critical' ? 'all' : 'critical'}
        class="p-3 rounded-xl text-center transition cursor-pointer border {activeFilter === 'critical' ? 'bg-red-900/40 border-red-700/80' : 'bg-(--color-bg-secondary) border-transparent hover:border-red-800/50'}">
        <p class="text-2xl font-bold text-(--color-severity-critical)">{summary.critical}</p>
        <p class="text-xs text-slate-400 mt-1">Critical</p>
      </button>
      <button onclick={() => activeFilter = activeFilter === 'high' ? 'all' : 'high'}
        class="p-3 rounded-xl text-center transition cursor-pointer border {activeFilter === 'high' ? 'bg-orange-900/40 border-orange-700/80' : 'bg-(--color-bg-secondary) border-transparent hover:border-orange-800/50'}">
        <p class="text-2xl font-bold text-(--color-severity-high)">{summary.high}</p>
        <p class="text-xs text-slate-400 mt-1">High</p>
      </button>
      <button onclick={() => activeFilter = activeFilter === 'medium' ? 'all' : 'medium'}
        class="p-3 rounded-xl text-center transition cursor-pointer border {activeFilter === 'medium' ? 'bg-yellow-900/40 border-yellow-700/80' : 'bg-(--color-bg-secondary) border-transparent hover:border-yellow-800/50'}">
        <p class="text-2xl font-bold text-(--color-severity-medium)">{summary.medium}</p>
        <p class="text-xs text-slate-400 mt-1">Medium</p>
      </button>
      <button onclick={() => activeFilter = activeFilter === 'low' ? 'all' : 'low'}
        class="p-3 rounded-xl text-center transition cursor-pointer border {activeFilter === 'low' ? 'bg-green-900/40 border-green-700/80' : 'bg-(--color-bg-secondary) border-transparent hover:border-green-800/50'}">
        <p class="text-2xl font-bold text-(--color-severity-low)">{summary.low}</p>
        <p class="text-xs text-slate-400 mt-1">Low</p>
      </button>
    </div>
  </div>

  <!-- Filter indicator -->
  {#if activeFilter !== 'all'}
    <div class="px-6 pb-2 flex items-center gap-2">
      <SeverityBadge severity={activeFilter} />
      <span class="text-xs text-slate-400">{sortedDetections().length}건 표시 중</span>
      <button onclick={() => activeFilter = 'all'} class="text-xs text-cyan-400 hover:text-cyan-300 ml-auto cursor-pointer">
        전체 보기
      </button>
    </div>
  {/if}

  <!-- Detection List -->
  <div class="flex-1 overflow-y-auto px-6 pb-4 space-y-2">
    {#if sortedDetections().length === 0}
      <div class="text-center py-12">
        <svg class="w-12 h-12 mx-auto text-green-500 mb-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        <p class="text-slate-300 font-medium">위협이 탐지되지 않았습니다</p>
        <p class="text-slate-500 text-sm mt-1">시스템이 안전한 상태입니다</p>
      </div>
    {:else}
      {#each sortedDetections() as detection (detection.id)}
        <DetectionCard
          {detection}
          expanded={expandedId === detection.id}
          ontoggle={() => toggleExpand(detection.id)}
        />
      {/each}
    {/if}
  </div>

  <!-- CTA Banner -->
  {#if totalDetections > 0}
    <div class="px-6 py-4 bg-gradient-to-r from-cyan-900/60 to-blue-900/60 border-t border-cyan-800/30">
      <div class="flex items-center justify-between">
        <div>
          <p class="text-sm font-medium text-white">AI 기반 상세 분석이 필요하신가요?</p>
          <p class="text-xs text-slate-400 mt-0.5">탐지된 위협에 대한 심층 분석과 대응 가이드를 받아보세요</p>
        </div>
        <button onclick={() => OpenBRIQA()} class="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium rounded-lg transition whitespace-nowrap cursor-pointer">
          BRIQA 분석 받기
        </button>
      </div>
    </div>
  {/if}
</div>
