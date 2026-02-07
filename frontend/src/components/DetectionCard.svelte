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

  const typeIcons = {
    lolbin_execution: 'M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z',
    suspicious_chain: 'M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1',
    suspicious_port: 'M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9',
    path_anomaly: 'M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z',
    typosquatting: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z',
    sigma_match: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z',
    persistence: 'M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15',
    service_vendor_typosquat: 'M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4',
    service_name_typosquat: 'M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0',
    service_path_anomaly: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2',
    unsigned_critical_process: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622',
    suspicious_domain: 'M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2V3.935',
    encoded_command: 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4',
  }
</script>

<button
  onclick={ontoggle}
  class="w-full text-left p-4 rounded-xl bg-(--color-bg-card) hover:bg-(--color-bg-elevated) border border-slate-800/40 hover:border-slate-700/50 transition-all cursor-pointer"
>
  <!-- Header Row -->
  <div class="flex items-start gap-3">
    <!-- Type Icon -->
    <div class="w-8 h-8 flex-shrink-0 flex items-center justify-center rounded-lg bg-slate-800/50">
      <svg class="w-4 h-4 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <path d={typeIcons[detection.type] || typeIcons.sigma_match} />
      </svg>
    </div>

    <div class="flex-1 min-w-0">
      <!-- User Description (primary) or Description fallback -->
      <p class="text-sm text-white font-medium leading-snug">
        {detection.user_description || detection.description}
      </p>
      <div class="flex items-center gap-2 mt-1">
        <SeverityBadge severity={detection.severity} />
        <span class="text-[10px] text-slate-500">{typeLabels[detection.type] || detection.type}</span>
      </div>
    </div>

    <svg class="w-4 h-4 text-slate-600 flex-shrink-0 transition-transform {expanded ? 'rotate-180' : ''}" viewBox="0 0 20 20" fill="currentColor">
      <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd"/>
    </svg>
  </div>

  <!-- Expanded Details -->
  {#if expanded}
    <div class="mt-3 pt-3 border-t border-slate-700/30 space-y-3">
      <!-- Technical Description (if different from user desc) -->
      {#if detection.user_description && detection.description !== detection.user_description}
        <div class="text-xs">
          <p class="text-slate-500 font-medium mb-0.5">Technical Detail</p>
          <p class="text-slate-400 font-mono text-[11px]">{detection.description}</p>
        </div>
      {/if}

      <!-- Recommendation -->
      {#if detection.recommendation}
        <div class="text-xs px-3 py-2 rounded-lg bg-cyan-900/15 border border-cyan-800/20">
          <p class="text-cyan-300/80">{detection.recommendation}</p>
        </div>
      {/if}

      <!-- Process Info -->
      {#if detection.process}
        <div class="text-xs space-y-1">
          <p class="text-slate-400 font-medium">Process Info</p>
          <div class="ml-3 space-y-0.5 text-slate-500">
            <!-- Process tree -->
            {#if detection.process.parent_name}
              <div class="flex items-center gap-1.5">
                <span class="text-slate-400">{detection.process.parent_name}</span>
                <svg class="w-3 h-3 text-slate-600" viewBox="0 0 20 20" fill="currentColor">
                  <path fill-rule="evenodd" d="M10.293 3.293a1 1 0 011.414 0l6 6a1 1 0 010 1.414l-6 6a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-4.293-4.293a1 1 0 010-1.414z" clip-rule="evenodd"/>
                </svg>
                <span class="text-slate-300 font-medium">{detection.process.name}</span>
                <span class="text-slate-600 text-[10px]">PID:{detection.process.pid}</span>
              </div>
            {:else}
              <p>Name: <span class="text-slate-300">{detection.process.name}</span> (PID: {detection.process.pid})</p>
            {/if}
            {#if detection.process.path}
              <p>Path: <span class="text-slate-300 break-all">{detection.process.path}</span></p>
            {/if}
            {#if detection.process.cmdline}
              <p>Command: <span class="text-slate-300 break-all font-mono text-[10px]">{detection.process.cmdline}</span></p>
            {/if}
          </div>
        </div>
      {/if}

      <!-- Network Info -->
      {#if detection.network}
        <div class="text-xs space-y-1">
          <p class="text-slate-400 font-medium">Network Info</p>
          <div class="ml-3 space-y-0.5 text-slate-500">
            <p>{detection.network.protocol}: <span class="text-slate-300">{detection.network.local_addr}:{detection.network.local_port}</span> → <span class="text-slate-300">{detection.network.remote_addr}:{detection.network.remote_port}</span></p>
            <p>State: <span class="text-slate-300">{detection.network.state}</span></p>
            {#if detection.network.process_name}
              <p>Process: <span class="text-slate-300">{detection.network.process_name}</span> (PID: {detection.network.owning_pid})</p>
            {/if}
          </div>
        </div>
      {/if}

      <!-- MITRE ATT&CK -->
      {#if detection.mitre}
        <div class="text-xs space-y-1">
          <p class="text-slate-400 font-medium">MITRE ATT&CK</p>
          <div class="ml-3 flex flex-wrap gap-1">
            {#each detection.mitre.tactics || [] as tactic}
              <span class="px-1.5 py-0.5 bg-blue-900/30 text-blue-300 rounded text-[10px] border border-blue-800/30">{tactic}</span>
            {/each}
            {#each detection.mitre.techniques || [] as technique}
              <span class="px-1.5 py-0.5 bg-purple-900/30 text-purple-300 rounded text-[10px] border border-purple-800/30">{technique}</span>
            {/each}
          </div>
        </div>
      {/if}

      <!-- Sigma Rules -->
      {#if detection.sigma_rules?.length}
        <div class="text-xs space-y-1">
          <p class="text-slate-400 font-medium">Sigma Rules</p>
          <div class="ml-3 flex flex-wrap gap-1">
            {#each detection.sigma_rules as rule}
              <span class="px-1.5 py-0.5 bg-cyan-900/30 text-cyan-300 rounded text-[10px] font-mono border border-cyan-800/30">{rule}</span>
            {/each}
          </div>
        </div>
      {/if}

      <!-- Confidence -->
      <div class="text-[11px] text-slate-600 pt-1">
        Confidence: {Math.round((detection.confidence || 0) * 100)}%
      </div>
    </div>
  {/if}
</button>
