<script>
  import SeverityBadge from './SeverityBadge.svelte'

  let { detection, expanded = false, ontoggle } = $props()

  const typeLabels = {
    lolbin_execution: 'LOLBin Execution',
    suspicious_chain: 'Suspicious Process Chain',
    suspicious_port: 'Suspicious Port',
    path_anomaly: 'Path Anomaly',
    typosquatting: 'Typosquatting',
    sigma_match: 'Sigma Rule Match',
    persistence: 'Persistence Mechanism',
    service_vendor_typosquat: 'Service Vendor Spoof',
    service_name_typosquat: 'Service Name Spoof',
    service_path_anomaly: 'Service Path Anomaly',
    unsigned_critical_process: 'Unsigned Process',
    suspicious_domain: 'Suspicious Domain',
    encoded_command: 'Encoded Command',
  }

  const sevColors = {
    critical: '#ff0040',
    high: '#ff8800',
    medium: '#ffb800',
    low: '#00ffff',
    info: '#555',
  }

  const barColor = $derived(sevColors[detection.severity] || '#555')
  const confidencePct = $derived(Math.round((detection.confidence || 0) * 100))
  const confidenceBlocks = $derived(Math.round(confidencePct / 5))
</script>

<button onclick={ontoggle} class="detection-card">
  <!-- Left severity color bar -->
  <div class="sev-bar" style="background:{barColor}; box-shadow: 0 0 6px {barColor}40;"></div>

  <div class="card-content">
    <!-- Header -->
    <div class="card-header">
      <div class="card-main">
        <p class="card-desc">{detection.user_description || detection.description}</p>
        <div class="card-meta">
          <SeverityBadge severity={detection.severity} />
          <span class="type-label mono-font">{typeLabels[detection.type] || detection.type}</span>
        </div>
      </div>
      <span class="expand-arrow" class:rotated={expanded}>&#x25BC;</span>
    </div>

    <!-- Expanded Details -->
    {#if expanded}
      <div class="card-details">
        <!-- Technical Description -->
        {#if detection.user_description && detection.description !== detection.user_description}
          <div class="detail-section">
            <div class="detail-label pixel-font">TECHNICAL</div>
            <p class="detail-text mono-font">{detection.description}</p>
          </div>
        {/if}

        <!-- Recommendation -->
        {#if detection.recommendation}
          <div class="detail-rec">
            <p class="mono-font">{detection.recommendation}</p>
          </div>
        {/if}

        <!-- Process Info -->
        {#if detection.process}
          <div class="detail-section">
            <div class="detail-label pixel-font">PROCESS</div>
            <div class="detail-text mono-font">
              {#if detection.process.parent_name}
                <div class="process-chain">
                  <span class="text-dim">{detection.process.parent_name}</span>
                  <span class="arrow">&#x2192;</span>
                  <span class="text-bright">{detection.process.name}</span>
                  <span class="text-dim" style="font-size:9px;">PID:{detection.process.pid}</span>
                </div>
              {:else}
                <p>{detection.process.name} <span class="text-dim">(PID: {detection.process.pid})</span></p>
              {/if}
              {#if detection.process.path}
                <p class="text-dim" style="word-break:break-all;">Path: <span class="text-bright">{detection.process.path}</span></p>
              {/if}
              {#if detection.process.cmdline}
                <div class="cmdline">{detection.process.cmdline}</div>
              {/if}
            </div>
          </div>
        {/if}

        <!-- Network Info -->
        {#if detection.network}
          <div class="detail-section">
            <div class="detail-label pixel-font">NETWORK</div>
            <div class="detail-text mono-font">
              <p>{detection.network.protocol}: <span class="text-bright">{detection.network.local_addr}:{detection.network.local_port}</span> &#x2192; <span class="text-bright">{detection.network.remote_addr}:{detection.network.remote_port}</span></p>
              <p>State: <span class="text-bright">{detection.network.state}</span></p>
              {#if detection.network.process_name}
                <p>Process: <span class="text-bright">{detection.network.process_name}</span> (PID: {detection.network.owning_pid})</p>
              {/if}
            </div>
          </div>
        {/if}

        <!-- MITRE ATT&CK -->
        {#if detection.mitre}
          <div class="detail-section">
            <div class="detail-label pixel-font">MITRE ATT&CK</div>
            <div class="mitre-tags">
              {#each detection.mitre.tactics || [] as tactic}
                <span class="mitre-tag tactic">{tactic}</span>
              {/each}
              {#each detection.mitre.techniques || [] as technique}
                <span class="mitre-tag technique">{technique}</span>
              {/each}
            </div>
          </div>
        {/if}

        <!-- Sigma Rules -->
        {#if detection.sigma_rules?.length}
          <div class="detail-section">
            <div class="detail-label pixel-font">SIGMA RULES</div>
            <div class="mitre-tags">
              {#each detection.sigma_rules as rule}
                <span class="mitre-tag sigma mono-font">{rule}</span>
              {/each}
            </div>
          </div>
        {/if}

        <!-- Confidence -->
        <div class="confidence-section">
          <span class="mono-font text-dim" style="font-size:10px;">Confidence: {confidencePct}%</span>
          <div class="conf-bar">
            {#each Array(20) as _, i}
              <div class="conf-block" style="background:{i < confidenceBlocks ? barColor : '#1a1a3a'};"></div>
            {/each}
          </div>
        </div>
      </div>
    {/if}
  </div>
</button>

<style>
  .detection-card {
    display: flex;
    width: 100%;
    text-align: left;
    background: #0d0d1a;
    border: 2px solid #1a1a3a;
    cursor: pointer;
    transition: border-color 0.2s;
    padding: 0;
    color: inherit;
    font: inherit;
  }
  .detection-card:hover {
    border-color: #2a2a5a;
  }
  .sev-bar {
    width: 4px;
    flex-shrink: 0;
  }
  .card-content {
    flex: 1;
    padding: 12px 14px;
    min-width: 0;
  }
  .card-header {
    display: flex;
    align-items: flex-start;
    gap: 8px;
  }
  .card-main { flex: 1; min-width: 0; }
  .card-desc {
    font-size: 12px;
    color: #e0e0f0;
    line-height: 1.5;
    margin-bottom: 6px;
  }
  .card-meta {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .type-label {
    font-size: 10px;
    color: #555;
  }
  .expand-arrow {
    color: #555;
    font-size: 10px;
    flex-shrink: 0;
    transition: transform 0.2s;
    margin-top: 2px;
  }
  .expand-arrow.rotated { transform: rotate(180deg); }

  .card-details {
    margin-top: 12px;
    padding-top: 10px;
    border-top: 1px solid #1a1a3a;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .detail-section { }
  .detail-label {
    font-size: 6px;
    color: #555;
    letter-spacing: 1px;
    margin-bottom: 4px;
  }
  .detail-text {
    font-size: 11px;
    color: #888;
    line-height: 1.5;
  }
  .text-dim { color: #555; }
  .text-bright { color: #c0c0d0; }
  .process-chain {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }
  .arrow { color: #00ffff; }
  .cmdline {
    margin-top: 4px;
    padding: 6px 8px;
    background: #080810;
    border: 1px solid #1a1a3a;
    color: #ff8800;
    font-size: 10px;
    font-family: var(--font-mono);
    word-break: break-all;
    line-height: 1.4;
  }
  .detail-rec {
    padding: 8px 10px;
    background: rgba(0, 255, 255, 0.03);
    border: 1px solid rgba(0, 255, 255, 0.15);
    font-size: 11px;
    color: #00ffff;
    line-height: 1.5;
  }
  .mitre-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .mitre-tag {
    padding: 2px 6px;
    font-size: 9px;
    border: 1px solid;
    font-family: var(--font-mono);
  }
  .mitre-tag.tactic {
    color: #ff00ff;
    border-color: #ff00ff40;
    background: rgba(255, 0, 255, 0.05);
  }
  .mitre-tag.technique {
    color: #ff00ff;
    border-color: #ff00ff40;
    background: rgba(255, 0, 255, 0.05);
  }
  .mitre-tag.sigma {
    color: #00ffff;
    border-color: #00ffff40;
    background: rgba(0, 255, 255, 0.05);
  }
  .confidence-section {
    display: flex;
    align-items: center;
    gap: 8px;
    padding-top: 4px;
  }
  .conf-bar {
    display: flex;
    gap: 1px;
    flex: 1;
  }
  .conf-block {
    flex: 1;
    height: 6px;
    transition: background 0.3s;
  }
</style>
