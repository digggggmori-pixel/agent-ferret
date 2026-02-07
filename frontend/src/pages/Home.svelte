<script>
  import { GetVersion, IsAdmin } from '../../wailsjs/go/main/App.js'
  import { onMount } from 'svelte'

  let { onstart } = $props()
  let version = $state('')
  let isAdmin = $state(false)
  let loading = $state(false)

  onMount(async () => {
    version = await GetVersion()
    isAdmin = await IsAdmin()
  })

  async function handleStart() {
    loading = true
    onstart()
  }
</script>

<div class="flex-1 flex flex-col items-center justify-center p-8">
  <!-- Logo Area -->
  <div class="mb-8 text-center">
    <div class="w-20 h-20 mx-auto mb-4 rounded-2xl bg-(--color-bg-secondary) border border-cyan-800/50 flex items-center justify-center">
      <svg class="w-12 h-12 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    </div>
    <h1 class="text-3xl font-bold text-white mb-2">Ferret</h1>
    <p class="text-sm text-cyan-400 font-medium tracking-wider uppercase">BRIQA Security Scanner</p>
  </div>

  <!-- Description -->
  <p class="text-slate-400 text-center mb-10 max-w-md leading-relaxed">
    내 PC에 보안 위협이 있는지 점검합니다.<br>
    프로세스, 네트워크, 서비스, 레지스트리, 이벤트 로그를 분석하여<br>
    의심스러운 활동을 탐지합니다.
  </p>

  <!-- Start Button -->
  <button
    onclick={handleStart}
    disabled={loading}
    class="group relative px-12 py-4 bg-cyan-600 hover:bg-cyan-500 disabled:bg-cyan-800 text-white font-semibold text-lg rounded-xl transition-all duration-200 shadow-lg shadow-cyan-900/50 hover:shadow-cyan-800/50 cursor-pointer"
  >
    {#if loading}
      <span class="flex items-center gap-2">
        <svg class="animate-spin w-5 h-5" viewBox="0 0 24 24" fill="none">
          <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="3" class="opacity-25"/>
          <path d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" fill="currentColor" class="opacity-75"/>
        </svg>
        준비 중...
      </span>
    {:else}
      점검 시작
    {/if}
  </button>

  <!-- Admin Notice -->
  {#if !isAdmin}
    <div class="mt-6 px-4 py-3 bg-amber-900/30 border border-amber-700/50 rounded-lg max-w-md">
      <p class="text-amber-300 text-sm text-center">
        관리자 권한으로 실행하면 더 정확한 결과를 얻을 수 있습니다.
      </p>
    </div>
  {/if}

  <!-- Footer -->
  <div class="mt-auto pt-8 text-center">
    <p class="text-slate-600 text-xs">Ferret v{version}</p>
  </div>
</div>
