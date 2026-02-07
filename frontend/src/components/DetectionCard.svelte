<script>
  import SeverityBadge from './SeverityBadge.svelte'

  let { detection, expanded = false, ontoggle } = $props()

  const typeLabels = {
    lolbin_execution: 'LOLBin 실행',
    suspicious_chain: '의심 프로세스 체인',
    suspicious_port: '의심 포트',
    path_anomaly: '경로 이상',
    typosquatting: '타이포스쿼팅',
    sigma_match: 'Sigma 룰 매칭',
    persistence: '지속성 메커니즘',
    service_vendor_typosquat: '서비스 벤더 위장',
    service_name_typosquat: '서비스명 위장',
    service_path_anomaly: '서비스 경로 이상',
    unsigned_critical_process: '미서명 프로세스',
    suspicious_domain: '의심 도메인',
    encoded_command: '인코딩된 명령어',
  }
</script>

<button
  onclick={ontoggle}
  class="w-full text-left p-4 rounded-xl bg-(--color-bg-secondary) hover:bg-(--color-bg-card) border border-slate-700/30 hover:border-slate-600/50 transition-all cursor-pointer"
>
  <!-- Header Row -->
  <div class="flex items-start gap-3">
    <SeverityBadge severity={detection.severity} />
    <div class="flex-1 min-w-0">
      <p class="text-sm text-white font-medium leading-snug">{detection.description}</p>
      <p class="text-xs text-slate-500 mt-1">{typeLabels[detection.type] || detection.type}</p>
    </div>
    <svg class="w-4 h-4 text-slate-500 flex-shrink-0 transition-transform {expanded ? 'rotate-180' : ''}" viewBox="0 0 20 20" fill="currentColor">
      <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd"/>
    </svg>
  </div>

  <!-- Expanded Details -->
  {#if expanded}
    <div class="mt-3 pt-3 border-t border-slate-700/50 space-y-2">
      <!-- Process Info -->
      {#if detection.process}
        <div class="text-xs space-y-1">
          <p class="text-slate-400 font-medium">프로세스 정보</p>
          <div class="ml-3 space-y-0.5 text-slate-500">
            <p>이름: <span class="text-slate-300">{detection.process.name}</span> (PID: {detection.process.pid})</p>
            {#if detection.process.parent_name}
              <p>부모: <span class="text-slate-300">{detection.process.parent_name}</span> (PID: {detection.process.ppid})</p>
            {/if}
            {#if detection.process.path}
              <p>경로: <span class="text-slate-300 break-all">{detection.process.path}</span></p>
            {/if}
            {#if detection.process.cmdline}
              <p>명령: <span class="text-slate-300 break-all font-mono text-[11px]">{detection.process.cmdline}</span></p>
            {/if}
          </div>
        </div>
      {/if}

      <!-- Network Info -->
      {#if detection.network}
        <div class="text-xs space-y-1">
          <p class="text-slate-400 font-medium">네트워크 정보</p>
          <div class="ml-3 space-y-0.5 text-slate-500">
            <p>{detection.network.protocol}: <span class="text-slate-300">{detection.network.local_addr}:{detection.network.local_port}</span> → <span class="text-slate-300">{detection.network.remote_addr}:{detection.network.remote_port}</span></p>
            <p>상태: <span class="text-slate-300">{detection.network.state}</span></p>
            {#if detection.network.process_name}
              <p>프로세스: <span class="text-slate-300">{detection.network.process_name}</span> (PID: {detection.network.owning_pid})</p>
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
              <span class="px-1.5 py-0.5 bg-blue-900/40 text-blue-300 rounded text-[10px]">{tactic}</span>
            {/each}
            {#each detection.mitre.techniques || [] as technique}
              <span class="px-1.5 py-0.5 bg-purple-900/40 text-purple-300 rounded text-[10px]">{technique}</span>
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
              <span class="px-1.5 py-0.5 bg-cyan-900/40 text-cyan-300 rounded text-[10px] font-mono">{rule}</span>
            {/each}
          </div>
        </div>
      {/if}

      <!-- Confidence -->
      <div class="text-xs text-slate-500 pt-1">
        신뢰도: {Math.round((detection.confidence || 0) * 100)}%
      </div>
    </div>
  {/if}
</button>
