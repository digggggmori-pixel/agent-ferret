<script>
  import { StartScan } from '../../wailsjs/go/main/App.js'
  import { EventsOn, EventsOff } from '../../wailsjs/runtime/runtime.js'
  import { onMount, onDestroy } from 'svelte'

  let { oncomplete } = $props()

  let progress = $state({
    step: 0, total: 8, stepName: 'Initializing...', percent: 0, detail: '', done: false
  })
  let elapsed = $state(0)
  let stepHistory = $state([])
  let detectionCount = $state(0)
  let timer = null

  const stepLabels = [
    '', 'Processes', 'Network Connections', 'Services',
    'Registry', 'Detection Engines', 'Sigma Rules',
    'Event Logs', 'Aggregation'
  ]

  const stepIcons = [
    '',
    'M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z',
    'M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9',
    'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2',
    'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z',
    'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z',
    'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z',
    'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2',
    'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z',
  ]

  onMount(async () => {
    timer = setInterval(() => { elapsed += 1 }, 1000)

    EventsOn('scan:progress', (data) => {
      progress = data

      if (data.step === 5 && data.detail) {
        const match = data.detail.match(/(\d+)/)
        if (match) detectionCount = parseInt(match[1])
      }

      const existingIdx = stepHistory.findIndex(s => s.step === data.step)
      if (existingIdx >= 0) {
        stepHistory[existingIdx] = { ...data }
      } else {
        stepHistory = [...stepHistory, { ...data }]
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

<div class="flex-1 flex flex-col p-6">
  <!-- Top -->
  <div class="text-center mb-6 animate-fade-in-up">
    <div class="w-14 h-14 mx-auto mb-3 rounded-full bg-cyan-900/30 border border-cyan-700/30 flex items-center justify-center">
      <svg class="w-7 h-7 text-cyan-400 animate-spin-slow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    </div>
    <h2 class="text-lg font-semibold text-white mb-0.5">Scanning in progress</h2>
    <p class="text-slate-500 text-xs">Elapsed: {formatTime(elapsed)}</p>
  </div>

  <!-- Progress Bar -->
  <div class="mb-6 animate-fade-in-up delay-1">
    <div class="flex justify-between text-xs mb-1.5">
      <span class="text-cyan-400 font-medium">{progress.stepName}</span>
      <span class="text-slate-500">{progress.percent}%</span>
    </div>
    <div class="w-full h-1.5 bg-(--color-bg-secondary) rounded-full overflow-hidden">
      <div
        class="h-full bg-gradient-to-r from-cyan-600 to-cyan-400 rounded-full transition-all duration-500 ease-out shimmer-bar"
        style="width: {progress.percent}%"
      ></div>
    </div>
  </div>

  <!-- Step List -->
  <div class="flex-1 space-y-1.5 overflow-y-auto">
    {#each Array(8) as _, i}
      {@const stepNum = i + 1}
      {@const historyItem = stepHistory.find(s => s.step === stepNum)}
      {@const isActive = progress.step === stepNum && !progress.done}
      {@const isDone = historyItem && (progress.step > stepNum || progress.done)}

      <div class="flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-300 {isActive ? 'bg-(--color-bg-card) border border-cyan-800/40' : isDone ? 'bg-(--color-bg-secondary)/40' : 'opacity-30'}">
        <div class="w-7 h-7 flex-shrink-0 flex items-center justify-center rounded-md {isActive ? 'bg-cyan-900/40' : isDone ? 'bg-slate-800/40' : ''}">
          {#if isDone}
            <svg class="w-4 h-4 text-cyan-400" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
            </svg>
          {:else if isActive}
            <svg class="w-4 h-4 text-cyan-400 animate-spin" viewBox="0 0 24 24" fill="none">
              <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="3" class="opacity-25"/>
              <path d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" fill="currentColor" class="opacity-75"/>
            </svg>
          {:else}
            <svg class="w-3.5 h-3.5 text-slate-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <path d={stepIcons[stepNum] || ''} />
            </svg>
          {/if}
        </div>

        <div class="flex-1 min-w-0">
          <p class="text-xs font-medium {isActive ? 'text-white' : isDone ? 'text-slate-300' : 'text-slate-600'}">
            {stepLabels[stepNum]}
          </p>
          {#if historyItem?.detail && (isActive || isDone)}
            <p class="text-[11px] text-slate-500 mt-0.5 truncate">{historyItem.detail}</p>
          {/if}
        </div>
      </div>
    {/each}
  </div>

  <!-- Detection counter -->
  {#if detectionCount > 0}
    <div class="mt-3 text-center animate-fade-in">
      <span class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-amber-900/20 border border-amber-800/30">
        <span class="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse"></span>
        <span class="text-xs text-amber-300">{detectionCount} detections found</span>
      </span>
    </div>
  {/if}
</div>
