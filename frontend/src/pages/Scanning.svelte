<script>
  import { StartScan } from '../../wailsjs/go/main/App.js'
  import { EventsOn, EventsOff } from '../../wailsjs/runtime/runtime.js'
  import { onMount, onDestroy } from 'svelte'

  let { oncomplete } = $props()

  let progress = $state({
    step: 0, total: 8, stepName: '초기화 중...', percent: 0, detail: '', done: false
  })
  let elapsed = $state(0)
  let stepHistory = $state([])
  let timer = null

  const stepLabels = [
    '', '프로세스 수집', '네트워크 연결 수집', '서비스 수집',
    '레지스트리 스캔', '탐지 엔진 실행', 'Sigma 룰 매칭',
    '이벤트 로그 분석', '결과 집계'
  ]

  onMount(async () => {
    timer = setInterval(() => { elapsed += 1 }, 1000)

    EventsOn('scan:progress', (data) => {
      progress = data

      // Update step history
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
      // Small delay to show completion state
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
    return m > 0 ? `${m}분 ${s}초` : `${s}초`
  }
</script>

<div class="flex-1 flex flex-col p-8">
  <!-- Header -->
  <div class="text-center mb-8">
    <h2 class="text-xl font-semibold text-white mb-1">보안 점검 진행 중</h2>
    <p class="text-slate-400 text-sm">경과 시간: {formatTime(elapsed)}</p>
  </div>

  <!-- Progress Bar -->
  <div class="mb-8">
    <div class="flex justify-between text-sm mb-2">
      <span class="text-cyan-400 font-medium">{progress.stepName}</span>
      <span class="text-slate-400">{progress.percent}%</span>
    </div>
    <div class="w-full h-2 bg-(--color-bg-secondary) rounded-full overflow-hidden">
      <div
        class="h-full bg-gradient-to-r from-cyan-600 to-cyan-400 rounded-full transition-all duration-500 ease-out"
        style="width: {progress.percent}%"
      ></div>
    </div>
  </div>

  <!-- Step List -->
  <div class="flex-1 space-y-2 overflow-y-auto">
    {#each Array(8) as _, i}
      {@const stepNum = i + 1}
      {@const historyItem = stepHistory.find(s => s.step === stepNum)}
      {@const isActive = progress.step === stepNum && !progress.done}
      {@const isDone = historyItem && (progress.step > stepNum || progress.done)}

      <div class="flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-300 {isActive ? 'bg-(--color-bg-secondary) border border-cyan-800/50' : isDone ? 'bg-(--color-bg-secondary)/50' : 'opacity-40'}">
        <!-- Status Icon -->
        <div class="w-6 h-6 flex-shrink-0 flex items-center justify-center">
          {#if isDone}
            <svg class="w-5 h-5 text-cyan-400" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
            </svg>
          {:else if isActive}
            <svg class="w-5 h-5 text-cyan-400 animate-spin" viewBox="0 0 24 24" fill="none">
              <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="3" class="opacity-25"/>
              <path d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" fill="currentColor" class="opacity-75"/>
            </svg>
          {:else}
            <div class="w-3 h-3 rounded-full bg-slate-600"></div>
          {/if}
        </div>

        <!-- Step Info -->
        <div class="flex-1 min-w-0">
          <p class="text-sm font-medium {isActive ? 'text-white' : isDone ? 'text-slate-300' : 'text-slate-500'}">
            Step {stepNum}. {stepLabels[stepNum]}
          </p>
          {#if historyItem?.detail && (isActive || isDone)}
            <p class="text-xs text-slate-500 mt-0.5 truncate">{historyItem.detail}</p>
          {/if}
        </div>
      </div>
    {/each}
  </div>

  <!-- Current Detail -->
  {#if progress.detail && !progress.done}
    <div class="mt-4 text-center">
      <p class="text-xs text-slate-500">{progress.detail}</p>
    </div>
  {/if}
</div>
