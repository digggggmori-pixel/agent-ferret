<script>
  let { severity } = $props()

  const styles = {
    critical: 'bg-red-900/50 text-red-300 border-red-700/50',
    high: 'bg-orange-900/50 text-orange-300 border-orange-700/50',
    medium: 'bg-yellow-900/50 text-yellow-300 border-yellow-700/50',
    low: 'bg-green-900/50 text-green-300 border-green-700/50',
    info: 'bg-slate-700/50 text-slate-300 border-slate-600/50',
  }

  const labels = {
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'MEDIUM',
    low: 'LOW',
    info: 'INFO',
  }
</script>

<span class="inline-flex items-center px-2 py-0.5 text-[10px] font-bold tracking-wider rounded border {styles[severity] || styles.info}">
  {labels[severity] || severity?.toUpperCase()}
</span>
