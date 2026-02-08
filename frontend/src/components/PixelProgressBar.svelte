<script>
  let { total = 8, filled = 0, warn = false } = $props()
</script>

<div class="pixel-progress">
  {#each Array(total) as _, i}
    <div
      class="block"
      class:filled={i < filled}
      class:warn={warn && i < filled}
    ></div>
  {/each}
</div>

<style>
  .pixel-progress {
    display: flex;
    gap: 3px;
  }
  .block {
    width: 100%;
    height: 14px;
    flex: 1;
    background: #1a1a3a;
    border: 1px solid #2a2a4a;
    transition: background 0.3s, box-shadow 0.3s;
  }
  .block.filled {
    background: #00ffff;
    border-color: #00ffff;
    box-shadow: 0 0 6px rgba(0, 255, 255, 0.4);
  }
  .block.warn {
    background: #ff8800;
    border-color: #ff8800;
    box-shadow: 0 0 6px rgba(255, 136, 0, 0.4);
  }
</style>
