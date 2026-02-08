<script>
  import { onMount, onDestroy } from 'svelte'
  import FerretMascot from './FerretMascot.svelte'

  let { currentStep = 0, detectionCount = 0 } = $props()

  let ferretX = $state(10)
  let ferretY = $state(70)
  let targetX = $state(10)
  let targetY = $state(70)
  let pose = $state('sleep')
  let speech = $state('')
  let facingLeft = $state(false)
  let alerts = $state([])
  let footprints = $state([])
  let scanning = $state(false)
  let done = $state(false)
  let prevDetections = 0
  let alertId = 0

  // Roaming loop — runs independently of scan steps
  let roamTimer = null
  let phase = $state('idle') // 'idle' | 'running' | 'sniffing' | 'found' | 'done'

  function randRange(min, max) {
    return min + Math.random() * (max - min)
  }

  function pickNextTarget() {
    // Pick a random spot, biased away from current position for variety
    let nx, ny, attempts = 0
    do {
      nx = randRange(8, 88)
      ny = randRange(15, 80)
      attempts++
    } while (Math.abs(nx - ferretX) < 15 && Math.abs(ny - ferretY) < 10 && attempts < 10)
    return { x: nx, y: ny }
  }

  function calcMoveDuration(fromX, fromY, toX, toY) {
    // Distance-based duration so speed feels consistent
    const dist = Math.sqrt((toX - fromX) ** 2 + (toY - fromY) ** 2)
    // ~30ms per % unit of distance, clamped 0.8s - 2.5s
    return Math.max(0.8, Math.min(dist * 30, 2500)) / 1000
  }

  function startRoaming() {
    if (done) return

    // Phase: run to a new spot
    const next = pickNextTarget()
    const dur = calcMoveDuration(ferretX, ferretY, next.x, next.y)

    // Leave footprint
    footprints = [...footprints.slice(-15), { x: ferretX, y: ferretY, id: Date.now() }]

    // Face direction of travel
    facingLeft = next.x < ferretX

    // Start moving
    phase = 'running'
    pose = 'run'
    speech = ''
    targetX = next.x
    targetY = next.y

    // After arrival: sniff for a bit then move again
    roamTimer = setTimeout(() => {
      ferretX = targetX
      ferretY = targetY
      phase = 'sniffing'
      pose = 'sniff'
      speech = ''

      // Sniff for 0.8-1.8s then move again
      const sniffTime = 800 + Math.random() * 1000
      roamTimer = setTimeout(() => {
        if (!done) startRoaming()
      }, sniffTime)
    }, dur * 1000)
  }

  function stopRoaming() {
    if (roamTimer) { clearTimeout(roamTimer); roamTimer = null }
  }

  // Start/stop roaming based on scan state
  $effect(() => {
    if (currentStep >= 1 && !scanning && !done) {
      // Scan just started — wake up and start roaming
      scanning = true
      pose = 'idle'
      speech = ''
      // Brief wake-up then start
      stopRoaming()
      roamTimer = setTimeout(() => startRoaming(), 400)
    }
    if (currentStep >= 8 && !done) {
      // Scan complete
      done = true
      stopRoaming()
      phase = 'done'
      // Run to center-ish
      facingLeft = 45 < ferretX
      targetX = 45
      targetY = 55
      pose = 'run'
      speech = ''
      roamTimer = setTimeout(() => {
        ferretX = 45
        ferretY = 55
        pose = 'happy'
        speech = 'All done!'
      }, 1000)
    }
  })

  // Detection alerts — interrupt briefly
  $effect(() => {
    if (detectionCount > prevDetections && detectionCount > 0) {
      const count = detectionCount
      prevDetections = count

      // Interrupt roaming briefly
      stopRoaming()
      phase = 'found'
      pose = 'found'
      speech = `Found ${count}!`

      // Show alert popup
      const aid = ++alertId
      alerts = [...alerts, { id: aid, x: ferretX, y: ferretY - 18, text: `! ${count} detected` }]
      setTimeout(() => { alerts = alerts.filter(a => a.id !== aid) }, 3000)

      // Resume roaming after 1.5s
      roamTimer = setTimeout(() => {
        if (!done) startRoaming()
      }, 1500)
    }
  })

  // Cleanup footprints periodically
  let cleanupTimer = null
  onMount(() => {
    cleanupTimer = setInterval(() => {
      const now = Date.now()
      footprints = footprints.filter(fp => now - fp.id < 5000)
    }, 2000)
  })

  onDestroy(() => {
    stopRoaming()
    if (cleanupTimer) clearInterval(cleanupTimer)
  })

  // CSS transition duration synced to movement
  const moveDur = $derived.by(() => {
    if (phase === 'running') {
      return calcMoveDuration(ferretX, ferretY, targetX, targetY)
    }
    if (phase === 'done') return 1
    return 0
  })
</script>

<div class="stage">
  <!-- Grid background -->
  <div class="grid-bg"></div>

  <!-- Subtle data nodes scattered around -->
  {#each [
    [18,25], [42,18], [72,38], [30,68], [58,62],
    [8,48], [82,22], [50,42], [65,75], [25,52],
    [88,58], [38,32], [75,68], [15,72], [55,28]
  ] as [nx, ny]}
    <div class="node" style="left:{nx}%; top:{ny}%;"></div>
  {/each}

  <!-- Footprints trail -->
  {#each footprints as fp (fp.id)}
    <div class="footprint" style="left:{fp.x}%; top:{fp.y}%;"></div>
  {/each}

  <!-- Alert popups -->
  {#each alerts as alert (alert.id)}
    <div class="alert-popup pixel-font" style="left:{alert.x}%; top:{alert.y}%;">
      {alert.text}
    </div>
  {/each}

  <!-- Ferret -->
  <div
    class="ferret-wrapper"
    class:flipped={facingLeft}
    style="
      left: {phase === 'running' || phase === 'done' ? targetX : ferretX}%;
      top: {phase === 'running' || phase === 'done' ? targetY : ferretY}%;
      transition: left {moveDur}s ease-in-out, top {moveDur}s ease-in-out;
    "
  >
    <FerretMascot {pose} scale={3} {speech} />
  </div>
</div>

<style>
  .stage {
    position: relative;
    width: 100%;
    height: 100%;
    min-height: 180px;
    background: #080810;
    border: 1px solid #1a1a3a;
    overflow: hidden;
  }
  .grid-bg {
    position: absolute;
    inset: 0;
    background-image:
      linear-gradient(rgba(0, 255, 255, 0.02) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0, 255, 255, 0.02) 1px, transparent 1px);
    background-size: 30px 30px;
  }

  .node {
    position: absolute;
    width: 3px;
    height: 3px;
    background: #1a1a3a;
    border-radius: 50%;
    transform: translate(-50%, -50%);
  }

  .footprint {
    position: absolute;
    width: 4px;
    height: 2px;
    background: rgba(0, 255, 255, 0.1);
    transform: translate(-50%, -50%);
    animation: fp-fade 5s ease-out forwards;
  }
  @keyframes fp-fade {
    0% { opacity: 1; }
    100% { opacity: 0; }
  }

  .alert-popup {
    position: absolute;
    transform: translate(-50%, -100%);
    font-size: 7px;
    color: #ff0040;
    text-shadow: 0 0 8px rgba(255, 0, 64, 0.6);
    padding: 4px 10px;
    border: 1px solid #ff004060;
    background: rgba(255, 0, 64, 0.1);
    white-space: nowrap;
    z-index: 10;
    animation: alert-in 0.3s ease-out, alert-out 0.5s 2.2s ease-out forwards;
  }
  @keyframes alert-in {
    from { transform: translate(-50%, -80%) scale(0.7); opacity: 0; }
    to { transform: translate(-50%, -100%) scale(1); opacity: 1; }
  }
  @keyframes alert-out {
    to { opacity: 0; transform: translate(-50%, -130%); }
  }

  .ferret-wrapper {
    position: absolute;
    transform: translate(-50%, -50%);
    z-index: 5;
  }
  .ferret-wrapper.flipped {
    transform: translate(-50%, -50%) scaleX(-1);
  }
</style>
