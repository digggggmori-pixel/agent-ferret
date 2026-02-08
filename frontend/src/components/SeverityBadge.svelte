<script>
  let { severity } = $props()

  const colors = {
    critical: '#ff0040',
    high: '#ff8800',
    medium: '#ffb800',
    low: '#00ffff',
    info: '#555',
  }

  const labels = {
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'MEDIUM',
    low: 'LOW',
    info: 'INFO',
  }

  const color = $derived(colors[severity] || colors.info)
</script>

<span
  class="pixel-font badge"
  style="color:{color}; border-color:{color}; text-shadow: 0 0 8px {color}40;"
>
  {labels[severity] || severity?.toUpperCase()}
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 6px;
    font-size: 6px;
    letter-spacing: 0.5px;
    border: 1px solid;
    background: rgba(0, 0, 0, 0.3);
  }
</style>
