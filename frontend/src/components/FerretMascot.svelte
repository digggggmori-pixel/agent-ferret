<script>
  import { onDestroy } from 'svelte'
  import { getPosePixels, pixelsToBoxShadow, getSpriteDimensions, runFrame1, runFrame2 } from '../lib/ferretPixelArt.js'

  let { pose = 'idle', scale = 5, animate = true, speech = '' } = $props()

  let runToggle = $state(false)
  let runInterval = null

  // For 'run' pose, alternate frames
  $effect(() => {
    if (runInterval) { clearInterval(runInterval); runInterval = null; }
    if (pose === 'run' && animate) {
      runInterval = setInterval(() => { runToggle = !runToggle }, 300)
    }
    return () => { if (runInterval) clearInterval(runInterval) }
  })

  const pixels = $derived.by(() => {
    if (pose === 'run') {
      return runToggle ? runFrame2() : runFrame1()
    }
    return getPosePixels(pose)
  })

  const boxShadow = $derived(pixelsToBoxShadow(pixels, scale))
  const dims = $derived(getSpriteDimensions(pixels, scale))

  const animClass = $derived.by(() => {
    if (!animate) return ''
    switch (pose) {
      case 'idle':  return 'animate-tail-wag'
      case 'sniff': return 'animate-head-bob'
      case 'found': return 'animate-alert-bounce'
      case 'happy': return 'animate-float'
      case 'sleep': return 'animate-breathe'
      default:      return ''
    }
  })

  onDestroy(() => { if (runInterval) clearInterval(runInterval) })
</script>

<div class="ferret-mascot {animClass}" style="display:inline-block; position:relative; width:{dims.width}px; height:{dims.height}px;">
  <div style="position:absolute; top:0; left:0; width:1px; height:1px; box-shadow:{boxShadow};"></div>
  {#if speech}
    <div class="speech-bubble pixel-font">{speech}</div>
  {/if}
</div>

<style>
  .speech-bubble {
    position: absolute;
    top: -32px;
    right: -120px;
    background: #181828;
    border: 2px solid #00ffff;
    border-radius: 4px;
    padding: 5px 8px;
    font-size: 7px;
    color: #00ffff;
    white-space: nowrap;
    box-shadow: 0 0 8px rgba(0, 255, 255, 0.2);
    z-index: 10;
  }
  .speech-bubble::before {
    content: '';
    position: absolute;
    left: -8px;
    top: 50%;
    transform: translateY(-50%);
    border: 4px solid transparent;
    border-right-color: #00ffff;
  }
</style>
