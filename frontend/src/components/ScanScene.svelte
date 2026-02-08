<script>
  import FerretMascot from './FerretMascot.svelte'

  let { currentStep = 0, detectionCount = 0 } = $props()

  const zones = [
    { label: 'PROC', icon: '[]' },
    { label: 'NET',  icon: '<>' },
    { label: 'SVC',  icon: '==' },
    { label: 'REG',  icon: '{}' },
    { label: 'DET',  icon: '!!' },
    { label: 'SIGMA',icon: '##' },
    { label: 'LOGS', icon: '>>' },
    { label: 'DONE', icon: 'OK' },
  ]

  // Zone state: inactive, active, completed, found
  function zoneState(zoneIndex) {
    const step = zoneIndex + 1
    if (currentStep > step || (currentStep === 8 && zoneIndex === 7)) return 'completed'
    if (currentStep === step) return 'active'
    return 'inactive'
  }

  // Ferret pose based on step
  const ferretPose = $derived.by(() => {
    if (currentStep === 0) return 'sleep'
    if (currentStep >= 8) return 'happy'
    // active step: alternate between run and sniff
    return 'sniff'
  })

  const ferretSpeech = $derived.by(() => {
    if (currentStep === 0) return ''
    if (currentStep >= 8) return 'All clear!'
    if (detectionCount > 0) return `Found ${detectionCount}!`
    return 'Hmm...'
  })
</script>

<div class="scan-scene">
  <div class="zone-grid">
    {#each zones as zone, i}
      {@const state = zoneState(i)}
      <div class="zone {state}" class:has-ferret={currentStep === i + 1}>
        <div class="zone-icon mono-font">{zone.icon}</div>
        <div class="zone-label pixel-font">{zone.label}</div>
        {#if state === 'completed'}
          <div class="zone-check neon-text-green">&#x2713;</div>
        {/if}
        {#if currentStep === i + 1}
          <div class="zone-ferret">
            <FerretMascot pose={ferretPose} scale={3} speech={ferretSpeech} />
          </div>
        {/if}
      </div>
    {/each}
  </div>
</div>

<style>
  .scan-scene {
    padding: 8px 0;
  }
  .zone-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 8px;
  }
  .zone {
    position: relative;
    background: #0a0a1a;
    border: 2px solid #1a1a3a;
    padding: 16px 8px 12px;
    text-align: center;
    transition: all 0.4s;
    min-height: 80px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 4px;
  }
  .zone-icon {
    font-size: 16px;
    color: #2a2a4a;
    transition: color 0.3s;
  }
  .zone-label {
    font-size: 7px;
    color: #333;
    transition: color 0.3s;
  }
  .zone.active {
    border-color: #00ffff;
    box-shadow: 0 0 12px rgba(0, 255, 255, 0.2), inset 0 0 12px rgba(0, 255, 255, 0.03);
  }
  .zone.active .zone-icon { color: #00ffff; }
  .zone.active .zone-label { color: #00ffff; }
  .zone.completed {
    border-color: #00ff4140;
    background: #0a1a0a;
  }
  .zone.completed .zone-icon { color: #00ff4180; }
  .zone.completed .zone-label { color: #00ff4180; }
  .zone-check {
    position: absolute;
    top: 4px;
    right: 6px;
    font-size: 12px;
  }
  .zone-ferret {
    position: absolute;
    top: -30px;
    left: 50%;
    transform: translateX(-50%);
    z-index: 5;
  }
  .has-ferret {
    padding-top: 24px;
  }
</style>
