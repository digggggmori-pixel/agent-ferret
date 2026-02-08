<script>
  import { onDestroy } from 'svelte'
  import FerretMascot from './FerretMascot.svelte'

  let { currentStep = 0, detectionCount = 0 } = $props()

  // Waypoints: ferret roams to these positions (% of stage)
  const waypoints = [
    { x: 8,  y: 75, label: '' },                // step 0: sleeping
    { x: 15, y: 60, label: 'Processes...' },     // step 1
    { x: 70, y: 25, label: 'Network...' },       // step 2
    { x: 85, y: 70, label: 'Services...' },      // step 3
    { x: 25, y: 20, label: 'Registry...' },      // step 4
    { x: 50, y: 50, label: 'Detectors...' },     // step 5
    { x: 78, y: 35, label: 'Sigma rules...' },   // step 6
    { x: 12, y: 40, label: 'Event logs...' },    // step 7
    { x: 45, y: 55, label: '' },                 // step 8: done
  ]

  let ferretX = $state(8)
  let ferretY = $state(75)
  let moving = $state(false)
  let pose = $state('sleep')
  let speech = $state('')
  let alerts = $state([])  // { id, x, y, text }
  let prevStep = $state(0)
  let prevDetections = $state(0)
  let moveTimer = null
  let alertId = 0

  // Footprints trail
  let footprints = $state([])

  $effect(() => {
    if (currentStep === prevStep) return
    const step = currentStep
    const wp = waypoints[step] || waypoints[0]

    // Add footprint at current position before moving
    if (prevStep > 0 && step > prevStep) {
      footprints = [...footprints.slice(-12), { x: ferretX, y: ferretY, id: Date.now() }]
    }

    if (step === 0) {
      pose = 'sleep'
      speech = ''
      ferretX = wp.x
      ferretY = wp.y
    } else if (step >= 8) {
      // Complete: run to center then happy
      moving = true
      pose = 'run'
      speech = ''
      ferretX = wp.x
      ferretY = wp.y
      if (moveTimer) clearTimeout(moveTimer)
      moveTimer = setTimeout(() => {
        moving = false
        pose = 'happy'
        speech = 'All done!'
      }, 800)
    } else {
      // Normal step: run to waypoint, then sniff
      moving = true
      pose = 'run'
      speech = ''
      ferretX = wp.x
      ferretY = wp.y

      if (moveTimer) clearTimeout(moveTimer)
      moveTimer = setTimeout(() => {
        moving = false
        pose = 'sniff'
        speech = wp.label
      }, 800)
    }

    prevStep = step
  })

  // Watch for new detections → show found pose + alert popup
  $effect(() => {
    if (detectionCount > prevDetections && detectionCount > 0) {
      const count = detectionCount
      // Switch to found pose
      if (moveTimer) clearTimeout(moveTimer)
      moving = false
      pose = 'found'
      speech = `Found ${count}!`

      // Add alert popup at ferret position
      const aid = ++alertId
      alerts = [...alerts, { id: aid, x: ferretX, y: ferretY - 15, text: `! ${count} detected` }]

      // After a bit, resume sniffing
      moveTimer = setTimeout(() => {
        pose = 'sniff'
        speech = waypoints[currentStep]?.label || 'Hmm...'
      }, 1500)

      // Fade out alert
      setTimeout(() => {
        alerts = alerts.filter(a => a.id !== aid)
      }, 2500)

      prevDetections = count
    }
  })

  onDestroy(() => { if (moveTimer) clearTimeout(moveTimer) })
</script>

<div class="stage">
  <!-- Grid background -->
  <div class="grid-bg"></div>

  <!-- Subtle data nodes -->
  <div class="node" style="left:20%; top:30%;"></div>
  <div class="node" style="left:50%; top:15%;"></div>
  <div class="node" style="left:75%; top:45%;"></div>
  <div class="node" style="left:35%; top:70%;"></div>
  <div class="node" style="left:60%; top:65%;"></div>
  <div class="node" style="left:10%; top:50%;"></div>
  <div class="node" style="left:85%; top:25%;"></div>
  <div class="node" style="left:45%; top:40%;"></div>

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

  <!-- Ground line -->
  <div class="ground"></div>

  <!-- Ferret -->
  <div
    class="ferret-wrapper"
    class:flipped={moving && ferretX < (waypoints[prevStep]?.x ?? ferretX)}
    style="left:{ferretX}%; top:{ferretY}%; transition: left {moving ? '0.8s' : '0s'} ease-in-out, top {moving ? '0.8s' : '0s'} ease-in-out;"
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
  .ground {
    position: absolute;
    bottom: 0;
    left: 0;
    right: 0;
    height: 1px;
    background: #1a1a3a;
  }

  /* Data nodes - subtle dots in the background */
  .node {
    position: absolute;
    width: 3px;
    height: 3px;
    background: #1a1a3a;
    border-radius: 50%;
    transform: translate(-50%, -50%);
  }

  /* Footprint trail */
  .footprint {
    position: absolute;
    width: 4px;
    height: 2px;
    background: rgba(0, 255, 255, 0.08);
    transform: translate(-50%, -50%);
    animation: footprint-fade 4s ease-out forwards;
  }
  @keyframes footprint-fade {
    from { opacity: 1; }
    to { opacity: 0; }
  }

  /* Alert popup */
  .alert-popup {
    position: absolute;
    transform: translate(-50%, -100%);
    font-size: 7px;
    color: #ff0040;
    text-shadow: 0 0 8px rgba(255, 0, 64, 0.6);
    padding: 3px 8px;
    border: 1px solid #ff004060;
    background: rgba(255, 0, 64, 0.08);
    white-space: nowrap;
    z-index: 10;
    animation: alert-pop 0.3s ease-out, alert-out 0.5s 2s ease-out forwards;
  }
  @keyframes alert-pop {
    from { transform: translate(-50%, -80%) scale(0.8); opacity: 0; }
    to { transform: translate(-50%, -100%) scale(1); opacity: 1; }
  }
  @keyframes alert-out {
    to { opacity: 0; transform: translate(-50%, -120%); }
  }

  /* Ferret container */
  .ferret-wrapper {
    position: absolute;
    transform: translate(-50%, -50%);
    z-index: 5;
  }
  .ferret-wrapper.flipped {
    transform: translate(-50%, -50%) scaleX(-1);
  }
</style>
