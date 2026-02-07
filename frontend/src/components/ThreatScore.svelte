<script>
  let { summary } = $props()

  const score = $derived(() => {
    const s = summary || { critical: 0, high: 0, medium: 0, low: 0 }
    const raw = s.critical * 40 + s.high * 15 + s.medium * 5 + s.low * 1
    return Math.min(raw, 100)
  })

  const grade = $derived(() => {
    const s = score()
    if (s === 0) return { label: 'Safe', color: '#22c55e' }
    if (s <= 20) return { label: 'Low Risk', color: '#22c55e' }
    if (s <= 50) return { label: 'Caution', color: '#eab308' }
    if (s <= 80) return { label: 'Warning', color: '#f97316' }
    return { label: 'Critical', color: '#ef4444' }
  })

  // SVG circle math: r=45, circumference=2*PI*45≈283
  const circumference = 283
  const dashOffset = $derived(() => circumference - (score() / 100) * circumference)
</script>

<div class="flex flex-col items-center">
  <div class="relative w-28 h-28">
    <svg class="w-full h-full -rotate-90" viewBox="0 0 100 100">
      <!-- Background circle -->
      <circle cx="50" cy="50" r="45" fill="none" stroke="#1e293b" stroke-width="8" />
      <!-- Score arc -->
      <circle
        cx="50" cy="50" r="45" fill="none"
        stroke={grade().color}
        stroke-width="8"
        stroke-linecap="round"
        stroke-dasharray={circumference}
        stroke-dashoffset={dashOffset()}
        style="transition: stroke-dashoffset 1s ease-out; animation: score-fill 1s ease-out;"
      />
    </svg>
    <!-- Center score -->
    <div class="absolute inset-0 flex flex-col items-center justify-center">
      <span class="text-2xl font-bold text-white">{score()}</span>
      <span class="text-[10px] text-slate-400 uppercase tracking-wider">/ 100</span>
    </div>
  </div>
  <p class="mt-2 text-sm font-semibold" style="color: {grade().color}">{grade().label}</p>
</div>
