<script>
  let { summary } = $props()

  const score = $derived(() => {
    const s = summary || { critical: 0, high: 0, medium: 0, low: 0 }
    const raw = s.critical * 40 + s.high * 15 + s.medium * 5 + s.low * 1
    return Math.min(raw, 100)
  })

  const grade = $derived(() => {
    const s = score()
    if (s === 0) return { label: 'SAFE', color: '#00ff41' }
    if (s <= 20) return { label: 'LOW', color: '#00ff41' }
    if (s <= 50) return { label: 'CAUTION', color: '#ffb800' }
    if (s <= 80) return { label: 'WARNING', color: '#ff8800' }
    return { label: 'CRITICAL', color: '#ff0040' }
  })

  const totalBlocks = 20
  const filledBlocks = $derived(() => Math.round((score() / 100) * totalBlocks))

  function blockColor(index) {
    const ratio = index / totalBlocks
    if (ratio < 0.25) return '#00ff41'
    if (ratio < 0.5) return '#ffb800'
    if (ratio < 0.75) return '#ff8800'
    return '#ff0040'
  }
</script>

<div class="threat-score">
  <div class="score-number pixel-font" style="color:{grade().color}; text-shadow: 0 0 20px {grade().color}60;">
    {score()}
  </div>
  <div class="score-label pixel-font" style="color:{grade().color};">{grade().label}</div>
  <div class="score-bar">
    {#each Array(totalBlocks) as _, i}
      <div
        class="bar-block"
        style="background:{i < filledBlocks() ? blockColor(i) : '#1a1a3a'}; box-shadow:{i < filledBlocks() ? `0 0 4px ${blockColor(i)}40` : 'none'};"
      ></div>
    {/each}
  </div>
  <div class="score-range mono-font">
    <span>0</span>
    <span style="color:#555;">/ 100</span>
  </div>
</div>

<style>
  .threat-score {
    display: flex;
    flex-direction: column;
    align-items: center;
    min-width: 100px;
  }
  .score-number {
    font-size: 28px;
    line-height: 1;
    margin-bottom: 4px;
  }
  .score-label {
    font-size: 7px;
    margin-bottom: 8px;
    letter-spacing: 1px;
  }
  .score-bar {
    display: flex;
    gap: 2px;
    width: 100%;
  }
  .bar-block {
    flex: 1;
    height: 8px;
    transition: background 0.3s, box-shadow 0.3s;
  }
  .score-range {
    display: flex;
    justify-content: space-between;
    width: 100%;
    font-size: 9px;
    color: #555;
    margin-top: 3px;
  }
</style>
