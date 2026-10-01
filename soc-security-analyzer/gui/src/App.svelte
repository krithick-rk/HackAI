<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { currentRoute, currentPath, navigate, initRouter } from './router';
  import { pickProjectDirectory } from './folderPicker';

  // Core API helper
  async function apiCall(endpoint: string, data: any = null, method: string = 'POST') {
    const options: RequestInit = {
      method,
      headers: { 'Content-Type': 'application/json' }
    };
    if (data && method !== 'GET') {
      options.body = JSON.stringify(data);
    }
    const res = await fetch(endpoint, options);
    if (!res.ok) {
      let errDetail = `HTTP ${res.status}`;
      try {
        const errJson = await res.json();
        errDetail = errJson.detail || errJson.message || JSON.stringify(errJson);
      } catch (_) {}
      throw new Error(errDetail);
    }
    return await res.json();
  }

  // Active View State
  type ViewName = 'home' | 'discovery' | 'modules' | 'analyze' | 'findings' | 'reports' | 'settings';
  let activeView: ViewName = 'home';

  // Project & Repository State
  let projectsList: Array<{ project_id: string; project_name: string; design_dir: string; modules_count: number; output_dir: string }> = [];
  let projectName: string = '';
  let designDir: string = '';
  let browseNotice: string = '';
  let browseLoading: boolean = false;
  let copyNotice: string = '';

  // Discovery State
  let discoveryData: any = null;
  let discoveryLoading: boolean = false;
  let discoveryError: string = '';

  // Modules State
  let dynamicModules: any[] = [];
  let moduleSearchText: string = '';
  let moduleStatusFilter: string = 'ALL';
  let selectedModuleDetail: any = null;
  let loadingModuleDetail: boolean = false;

  // Analysis State
  let analysisScope: 'entire' | 'selected_modules' = 'entire';
  let selectedAnalysisModules: string[] = [];
  let analysisTypes = {
    structural: true,
    data_control_flow: true,
    reachability: true,
    ai_assisted: false,
    validation: true
  };
  let selectedAIProvider: string = 'automatic';
  let analysisJob: any = {
    job_id: null,
    status: 'IDLE',
    progress_pct: 0,
    current_stage: 'Ready',
    current_module: '',
    current_file: '',
    stages: [],
    module_queue: [],
    findings: [],
    logs: []
  };
  let analysisPollingInterval: any = null;
  let startingAnalysis: boolean = false;

  // Findings State
  let findingsList: any[] = [];
  let findingsLoading: boolean = false;
  let findingsError: string = '';
  let findingSearchText: string = '';
  let findingSeverityFilter: string = 'ALL';
  let findingStatusFilter: string = 'ALL';
  let findingModuleFilter: string = 'ALL';
  let selectedFindingModal: any = null;
  let sourceSnippet: any = null;
  let sourceSnippetLoading: boolean = false;
  let sourceSnippetVisible: boolean = false;
  let revalidating: boolean = false;
  let revalidateMessage: string = '';

  // AI Provider State
  let aiProvidersCatalog: any[] = [];
  let aiDefaultProvider: string = 'automatic';
  let aiUsageData: any = null;
  let showAIConfigModal: boolean = false;
  let editingProvider: any = null;
  let editingApiKey: string = '';
  let editingEndpoint: string = '';
  let editingModel: string = '';
  let showApiKeyPlain: boolean = false;
  let testingConnection: boolean = false;
  let testConnectionResult: { status: string; message: string; latency_ms?: number } | null = null;
  let savingProvider: boolean = false;

  // Reports State
  let reportsList: any[] = [];
  let activeReportSummary: any = null;
  let reportsLoading: boolean = false;

  function copyToClipboard(text: string) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      copyNotice = 'Copied to clipboard!';
      setTimeout(() => { copyNotice = ''; }, 2500);
    }).catch(err => {
      console.error('Clipboard copy failed:', err);
    });
  }

  // --- Fetchers ---

  async function fetchProjects() {
    try {
      const res = await apiCall('/api/projects', null, 'GET');
      projectsList = res.projects || [];
    } catch (e) {
      console.error('Failed to list projects:', e);
    }
  }

  async function fetchDiscovery() {
    if (!projectName && !designDir) return;
    discoveryLoading = true;
    discoveryError = '';
    try {
      if (projectName) {
        discoveryData = await apiCall(`/api/projects/${projectName}/discovery`, null, 'GET');
      } else if (designDir) {
        discoveryData = await apiCall('/api/projects/discover', { path: designDir });
      }
      if (discoveryData && discoveryData.modules) {
        dynamicModules = discoveryData.modules;
      }
    } catch (e: any) {
      discoveryError = e.message || 'Discovery data not available.';
    } finally {
      discoveryLoading = false;
    }
  }

  async function fetchProjectModules() {
    if (!projectName) return;
    try {
      const res = await apiCall(`/api/projects/${projectName}/modules`, null, 'GET');
      dynamicModules = res.modules || [];
    } catch (e) {
      console.error('Failed to load modules:', e);
    }
  }

  async function openModuleDetail(modName: string) {
    loadingModuleDetail = true;
    selectedModuleDetail = null;
    try {
      const res = await apiCall(`/api/projects/${projectName || 'default'}/modules/${modName}`, null, 'GET');
      selectedModuleDetail = res;
    } catch (e) {
      console.error('Failed to load module details:', e);
      selectedModuleDetail = { name: modName, error: 'Failed to load module details.' };
    } finally {
      loadingModuleDetail = false;
    }
  }

  async function fetchAnalysisStatus() {
    try {
      const res = await apiCall(`/api/projects/${projectName || 'default'}/analysis/status`, null, 'GET');
      analysisJob = res;
      if (analysisJob.status === 'RUNNING') {
        startAnalysisPolling();
      } else if (analysisJob.status === 'COMPLETED' || analysisJob.status === 'FAILED') {
        stopAnalysisPolling();
      }
    } catch (e) {
      console.error('Failed to fetch analysis status:', e);
    }
  }

  function startAnalysisPolling() {
    if (analysisPollingInterval) return;
    analysisPollingInterval = setInterval(async () => {
      try {
        const res = await apiCall(`/api/projects/${projectName || 'default'}/analysis/status`, null, 'GET');
        analysisJob = res;
        if (analysisJob.status !== 'RUNNING') {
          stopAnalysisPolling();
          if (analysisJob.status === 'COMPLETED') {
            fetchFindings();
          }
        }
      } catch (_) {
        stopAnalysisPolling();
      }
    }, 1200);
  }

  function stopAnalysisPolling() {
    if (analysisPollingInterval) {
      clearInterval(analysisPollingInterval);
      analysisPollingInterval = null;
    }
  }

  async function triggerStartAnalysis() {
    if (!designDir && !projectName) {
      browseNotice = 'Please select a repository first.';
      return;
    }
    startingAnalysis = true;
    try {
      const payload = {
        project_name: projectName,
        scope: analysisScope,
        modules: selectedAnalysisModules,
        analysis_types: analysisTypes,
        ai_provider: selectedAIProvider
      };
      await apiCall('/api/analyze', payload);
      activeView = 'analyze';
      navigate(`/projects/${projectName || 'default'}/analyze`);
      startAnalysisPolling();
    } catch (e: any) {
      alert(`Failed to start analysis: ${e.message}`);
    } finally {
      startingAnalysis = false;
    }
  }

  async function fetchFindings() {
    findingsLoading = true;
    findingsError = '';
    try {
      const res = await apiCall('/api/v2/findings', null, 'GET');
      findingsList = res.findings || [];
    } catch (e: any) {
      findingsError = e.message || 'Failed to fetch findings.';
    } finally {
      findingsLoading = false;
    }
  }

  async function openFindingModal(finding: any) {
    selectedFindingModal = finding;
    sourceSnippet = null;
    sourceSnippetVisible = false;
    revalidateMessage = '';
  }

  async function openFindingModalById(fId: string) {
    try {
      const f = await apiCall(`/api/v2/finding/${fId}`, null, 'GET');
      openFindingModal(f);
    } catch (e) {
      console.error('Finding not found:', e);
    }
  }

  async function loadSourceSnippet(filePath: string, line: number) {
    sourceSnippetLoading = true;
    sourceSnippet = null;
    sourceSnippetVisible = true;
    try {
      const res = await apiCall(`/api/source/snippet?file=${encodeURIComponent(filePath)}&line=${line}&project_id=${projectName || ''}`, null, 'GET');
      sourceSnippet = res;
    } catch (e: any) {
      sourceSnippet = { error: e.message || 'Failed to load source snippet.' };
    } finally {
      sourceSnippetLoading = false;
    }
  }

  async function triggerRevalidateFinding(findingId: string) {
    revalidating = true;
    revalidateMessage = '';
    try {
      const res = await apiCall(`/api/findings/${findingId}/revalidate?project_id=${projectName || ''}`, null, 'POST');
      if (res.status === 'ok') {
        revalidateMessage = `✅ Revalidated: ${res.validation_status} - ${res.validation_reason}`;
        if (selectedFindingModal && selectedFindingModal.finding_id === findingId) {
          selectedFindingModal.validation_status = res.validation_status;
          selectedFindingModal.validation_reason = res.validation_reason;
        }
        fetchFindings();
      } else {
        revalidateMessage = `⚠️ ${res.message || 'Revalidation failed'}`;
      }
    } catch (e: any) {
      revalidateMessage = `Error: ${e.message}`;
    } finally {
      revalidating = false;
    }
  }

  async function fetchAIProviders() {
    try {
      const res = await apiCall('/api/ai/providers', null, 'GET');
      aiProvidersCatalog = res.providers || [];
      aiDefaultProvider = res.default_provider || 'automatic';
      const usageRes = await apiCall('/api/ai/usage', null, 'GET');
      aiUsageData = usageRes;
    } catch (e) {
      console.error('Failed to load AI providers:', e);
    }
  }

  function openEditProviderModal(provider: any) {
    editingProvider = provider;
    editingApiKey = '';
    editingEndpoint = provider.endpoint || '';
    editingModel = provider.default_model || '';
    showApiKeyPlain = false;
    testConnectionResult = null;
    showAIConfigModal = true;
  }

  async function runTestConnection() {
    if (!editingProvider) return;
    testingConnection = true;
    testConnectionResult = null;
    try {
      const payload: any = {
        provider: editingProvider.id,
        api_key: editingApiKey || undefined,
        endpoint: editingEndpoint || undefined
      };
      const res = await apiCall('/api/ai/test', payload);
      testConnectionResult = res;
    } catch (e: any) {
      testConnectionResult = { status: 'error', message: e.message || 'Test failed' };
    } finally {
      testingConnection = false;
    }
  }

  async function saveProviderConfig() {
    if (!editingProvider) return;
    savingProvider = true;
    try {
      const payload = {
        provider: editingProvider.id,
        name: editingProvider.name,
        api_key: editingApiKey || undefined,
        endpoint: editingEndpoint,
        model: editingModel,
        enabled: true
      };
      await apiCall('/api/ai/providers', payload);
      showAIConfigModal = false;
      fetchAIProviders();
    } catch (e: any) {
      alert(`Failed to save: ${e.message}`);
    } finally {
      savingProvider = false;
    }
  }

  async function fetchReports() {
    reportsLoading = true;
    try {
      const res = await apiCall('/api/reports', null, 'GET');
      reportsList = res.reports || [];
      activeReportSummary = await apiCall('/api/v2/run/summary', null, 'GET');
    } catch (e) {
      console.error('Failed to fetch reports:', e);
    } finally {
      reportsLoading = false;
    }
  }

  // --- Folder Selection & Discovery Workflow ---

  async function handleBrowseProjectFolder() {
    browseNotice = 'Opening system directory picker...';
    try {
      const res = await pickProjectDirectory(projectName || 'new_project', {
        title: 'Select SoC / RTL Repository Folder'
      });
      if (res.status === 'selected' && res.path) {
        browseNotice = `Selected repository: ${res.path}`;
        const folderName = res.name || res.path.split('/').filter(Boolean).pop() || 'project';
        const cleanName = folderName.toLowerCase().replace(/[^a-z0-9_\-]/g, '_');
        await runDiscoveryOnPath(res.path, cleanName);
      } else if (res.status === 'cancelled') {
        browseNotice = '';
      } else if (res.status === 'error') {
        browseNotice = `Directory picker note: ${res.error || 'Please enter path below.'}`;
      }
    } catch (err: any) {
      browseNotice = `Picker note: ${err.message || err}`;
    }
  }

  async function runDiscoveryOnPath(path: string, cleanName: string) {
    discoveryLoading = true;
    discoveryError = '';
    try {
      const disc = await apiCall('/api/projects/discover', { path, project_name: cleanName });
      discoveryData = disc;
      projectName = cleanName || disc.repository_name;
      designDir = path;
      dynamicModules = disc.modules || [];
      activeView = 'discovery';
      navigate(`/projects/${projectName}/discovery`);
      fetchProjects();
    } catch (e: any) {
      discoveryError = e.message || 'Failed to scan repository.';
    } finally {
      discoveryLoading = false;
    }
  }

  async function openExistingProject(proj: any) {
    projectName = proj.project_name || proj.project_id;
    designDir = proj.design_dir || '';
    activeView = 'discovery';
    navigate(`/projects/${projectName}/discovery`);
    fetchDiscovery();
  }

  async function deleteProject(projId: string) {
    if (!confirm(`Are you sure you want to remove project "${projId}"?`)) return;
    try {
      await apiCall(`/api/projects/${projId}`, null, 'DELETE');
      fetchProjects();
      if (projectName === projId) {
        projectName = '';
        designDir = '';
        activeView = 'home';
        navigate('/');
      }
    } catch (e) {
      console.error('Delete project failed:', e);
    }
  }

  // Router listener
  function handleRouteChange(r: any) {
    if (!r) return;
    if (r.name === 'root' || r.name === 'projects') {
      activeView = 'home';
      fetchProjects();
    } else if (r.name === 'project_detail') {
      if (r.params.id) {
        projectName = r.params.id;
        activeView = 'discovery';
        fetchDiscovery();
      }
    } else if (r.name === 'project_discovery') {
      activeView = 'discovery';
      if (r.params.id && r.params.id !== projectName) {
        projectName = r.params.id;
      }
      fetchDiscovery();
    } else if (r.name === 'project_modules') {
      activeView = 'modules';
      if (r.params.id && r.params.id !== projectName) {
        projectName = r.params.id;
      }
      fetchProjectModules();
    } else if (r.name === 'project_analyze') {
      activeView = 'analyze';
      if (r.params.id && r.params.id !== projectName) {
        projectName = r.params.id;
      }
      fetchAnalysisStatus();
    } else if (r.name === 'findings') {
      activeView = 'findings';
      fetchFindings();
    } else if (r.name === 'finding_detail') {
      activeView = 'findings';
      fetchFindings().then(() => {
        if (r.params.id) openFindingModalById(r.params.id);
      });
    } else if (r.name === 'reports') {
      activeView = 'reports';
      fetchReports();
    } else if (r.name === 'settings') {
      activeView = 'settings';
      fetchAIProviders();
    } else if (r.name === 'dashboard') {
      if (projectName) {
        activeView = 'discovery';
        fetchDiscovery();
      } else {
        activeView = 'home';
        fetchProjects();
      }
    }
  }

  $: handleRouteChange($currentRoute);

  onMount(() => {
    const cleanupRouter = initRouter();
    fetchProjects();
    fetchFindings();
    fetchAIProviders();
    return () => {
      if (cleanupRouter) cleanupRouter();
      stopAnalysisPolling();
    };
  });

  onDestroy(() => {
    stopAnalysisPolling();
  });

  // Filtered Modules
  $: filteredDynamicModules = dynamicModules.filter(m => {
    if (moduleSearchText && !m.name.toLowerCase().includes(moduleSearchText.toLowerCase())) return false;
    if (moduleStatusFilter !== 'ALL') {
      if (moduleStatusFilter === 'WITH_FINDINGS' && (m.findings_count || 0) === 0) return false;
      if (moduleStatusFilter === 'NOT_ANALYZED' && m.analysis_status !== 'NOT_ANALYZED') return false;
    }
    return true;
  });

  // Filtered Findings
  $: filteredFindings = findingsList.filter(f => {
    if (findingSearchText) {
      const q = findingSearchText.toLowerCase();
      const match = (f.title || f.human_title || '').toLowerCase().includes(q) ||
                    (f.weakness_class || '').toLowerCase().includes(q) ||
                    (f.file || f.source || '').toLowerCase().includes(q) ||
                    (f.definition_id || f.module || '').toLowerCase().includes(q) ||
                    (f.what_is_wrong || '').toLowerCase().includes(q);
      if (!match) return false;
    }
    if (findingSeverityFilter !== 'ALL' && (f.severity || '').toUpperCase() !== findingSeverityFilter) return false;
    if (findingStatusFilter !== 'ALL') {
      const st = (f.validation_status || f.status || '').toUpperCase();
      if (st !== findingStatusFilter) return false;
    }
    if (findingModuleFilter !== 'ALL') {
      const m = f.definition_id || f.module || '';
      if (m !== findingModuleFilter) return false;
    }
    return true;
  });

  // Dynamic modules list for findings dropdown
  $: modulesForFindingsFilter = Array.from(new Set(findingsList.map(f => f.definition_id || f.module).filter(Boolean))).sort();
</script>

<main class="dashboard-root">
  <!-- Top Navigation Header -->
  <header class="header">
    <div class="logo" role="button" tabindex="0" on:click={() => navigate('/')} on:keydown={(e) => e.key === 'Enter' && navigate('/')}>
      <span class="pulse-dot"></span>
      <h1>SoC Security Analyzer</h1>
    </div>

    <!-- Active Project Breadcrumb / Badge -->
    {#if projectName}
      <div class="project-pill" title={designDir}>
        <span class="pill-label">Project:</span>
        <strong>{projectName}</strong>
      </div>
    {/if}

    <!-- Main Navigation Bar -->
    <nav class="header-nav">
      <button class="nav-btn {activeView === 'home' ? 'active' : ''}" on:click={() => navigate('/')}>
        🏠 Home
      </button>

      {#if projectName}
        <button class="nav-btn {activeView === 'discovery' ? 'active' : ''}" on:click={() => navigate(`/projects/${projectName}/discovery`)}>
          🔎 Discovery
        </button>
        <button class="nav-btn {activeView === 'modules' ? 'active' : ''}" on:click={() => navigate(`/projects/${projectName}/modules`)}>
          📦 Modules
        </button>
        <button class="nav-btn {activeView === 'analyze' ? 'active' : ''}" on:click={() => navigate(`/projects/${projectName}/analyze`)}>
          🚀 Analysis
        </button>
      {/if}

      <button class="nav-btn {activeView === 'findings' ? 'active' : ''}" on:click={() => navigate('/findings')}>
        🚨 Findings
      </button>

      <button class="nav-btn {activeView === 'reports' ? 'active' : ''}" on:click={() => navigate('/reports')}>
        📄 Reports
      </button>

      <button class="nav-btn {activeView === 'settings' ? 'active' : ''}" on:click={() => navigate('/settings')}>
        ⚙️ AI Settings
      </button>
    </nav>

    <div class="status-indicator">
      {#if analysisJob.status === 'RUNNING'}
        <span class="badge running">Analyzing ({analysisJob.progress_pct}%)</span>
      {:else}
        <span class="badge idle">Analyzer Ready</span>
      {/if}
    </div>
  </header>

  <div class="content-container">
    {#if copyNotice}
      <div class="toast-notice">{copyNotice}</div>
    {/if}

    <!-- ================================================================= -->
    <!-- VIEW 1: HOME / PROJECT SELECTION SCREEN -->
    <!-- ================================================================= -->
    {#if activeView === 'home'}
      <section class="home-container">
        <!-- Hero Banner -->
        <div class="hero-card card glass">
          <div class="hero-badge">Hardware & RTL Security Verification</div>
          <h2>SoC Security Analyzer</h2>
          <p class="hero-description">
            Analyze hardware and software repositories for security vulnerabilities using deterministic static analysis,
            symbolic data/control-flow reasoning, Z3 reachability analysis, and evidence-based witness validation.
          </p>

          <div class="hero-cta-area">
            <button class="btn btn-primary btn-lg" on:click={handleBrowseProjectFolder}>
              📂 Browse Repository
            </button>
            <span class="or-divider">or enter directory path:</span>
            <div class="input-with-btn quick-path-row">
              <input type="text" bind:value={designDir} placeholder="/path/to/hardware/repository" class="path-input" />
              <button class="btn btn-secondary" on:click={() => {
                if (designDir.trim()) {
                  const name = designDir.trim().split('/').filter(Boolean).pop() || 'project';
                  runDiscoveryOnPath(designDir.trim(), name.toLowerCase().replace(/[^a-z0-9_\-]/g, '_'));
                }
              }}>
                Discover
              </button>
            </div>
          </div>

          {#if browseNotice}
            <div class="alert notice" style="margin-top: 1rem;">{browseNotice}</div>
          {/if}
          {#if discoveryLoading}
            <div class="loading-bar-row">
              <span class="spinner"></span> Scanning directory structure and extracting modules...
            </div>
          {/if}
        </div>

        <!-- Recent Projects Section -->
        <div class="recent-projects-card card glass">
          <div class="section-header">
            <h3>Recent Projects</h3>
            <span class="subtext">Select a saved project to inspect modules or run security verification.</span>
          </div>

          {#if projectsList.length === 0}
            <div class="empty-state">
              <span class="empty-icon">📁</span>
              <p>No projects yet.<br />Select a repository to begin.</p>
            </div>
          {:else}
            <div class="projects-grid">
              {#each projectsList as proj}
                <div class="project-card card glass" on:click={() => openExistingProject(proj)}>
                  <div class="project-card-header">
                    <h4>{proj.project_name || proj.project_id}</h4>
                    <span class="badge badge-info">{proj.modules_count} modules</span>
                  </div>
                  <div class="project-path" title={proj.design_dir}>
                    {proj.design_dir || 'Path not specified'}
                  </div>
                  <div class="project-card-footer">
                    <button class="btn btn-sm btn-primary" on:click|stopPropagation={() => openExistingProject(proj)}>
                      Open Project
                    </button>
                    <button class="btn btn-sm btn-secondary danger-text" on:click|stopPropagation={() => deleteProject(proj.project_id)}>
                      Delete
                    </button>
                  </div>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      </section>
    {/if}

    <!-- ================================================================= -->
    <!-- VIEW 2: REPOSITORY DISCOVERY SUMMARY -->
    <!-- ================================================================= -->
    {#if activeView === 'discovery'}
      <section class="discovery-container">
        <div class="discovery-header-card card glass">
          <div class="header-left">
            <span class="section-tag">Repository Discovery</span>
            <h2>{discoveryData?.repository_name || projectName || 'Repository'}</h2>
            <div class="repo-path-display">
              <span class="path-label">Location:</span>
              <code>{discoveryData?.path || designDir}</code>
              <button class="btn-copy" on:click={() => copyToClipboard(discoveryData?.path || designDir)}>📋</button>
            </div>
          </div>
          <div class="header-actions">
            {#if discoveryData?.readiness?.status === 'READY'}
              <span class="badge badge-success big-badge">✓ Ready for Analysis</span>
            {:else}
              <span class="badge badge-warning big-badge">{discoveryData?.readiness?.status || 'Validating'}</span>
            {/if}
            <button class="btn btn-primary" on:click={() => navigate(`/projects/${projectName}/analyze`)}>
              🚀 Configure & Start Analysis
            </button>
          </div>
        </div>

        {#if discoveryError}
          <div class="alert alert-error">{discoveryError}</div>
        {/if}

        <!-- Metric Stat Cards Grid -->
        <div class="stats-grid">
          <div class="stat-card card glass">
            <span class="stat-number">{discoveryData?.counts?.sv_files || 0}</span>
            <span class="stat-label">SystemVerilog Files</span>
          </div>
          <div class="stat-card card glass">
            <span class="stat-number">{discoveryData?.counts?.v_files || 0}</span>
            <span class="stat-label">Verilog Files</span>
          </div>
          <div class="stat-card card glass">
            <span class="stat-number">{discoveryData?.counts?.c_cpp_files || 0}</span>
            <span class="stat-label">C/C++ Files</span>
          </div>
          <div class="stat-card card glass">
            <span class="stat-number">{discoveryData?.counts?.config_files || 0}</span>
            <span class="stat-label">Configuration Files</span>
          </div>
          <div class="stat-card card glass highlight-stat">
            <span class="stat-number">{discoveryData?.counts?.modules_discovered || dynamicModules.length || 0}</span>
            <span class="stat-label">Modules Discovered</span>
          </div>
          <div class="stat-card card glass">
            <span class="stat-number">{discoveryData?.counts?.total_files || 0}</span>
            <span class="stat-label">Total Scanned Files</span>
          </div>
        </div>

        <!-- Languages & Configs Summary Row -->
        <div class="details-split-row">
          <div class="card glass split-card">
            <h3>Detected Hardware / Software Components</h3>
            <div class="chip-container">
              {#if discoveryData?.languages && discoveryData.languages.length > 0}
                {#each discoveryData.languages as lang}
                  <span class="chip chip-accent">{lang}</span>
                {/each}
              {:else}
                <span class="chip">Hardware RTL</span>
              {/if}
            </div>

            <h4 style="margin-top: 1.5rem;">Important Directories</h4>
            <div class="chip-container">
              {#if discoveryData?.important_dirs && discoveryData.important_dirs.length > 0}
                {#each discoveryData.important_dirs as dir}
                  <span class="chip chip-dim">📁 {dir}</span>
                {/each}
              {:else}
                <span class="subtext">Top-level root directory</span>
              {/if}
            </div>
          </div>

          <div class="card glass split-card">
            <h3>Discovered Configurations & Tool Support</h3>
            <div class="readiness-box">
              <p><strong>Status:</strong> {discoveryData?.readiness?.message || 'Ready for static analysis.'}</p>
              <div class="tools-status-row">
                <span class="tool-tag {discoveryData?.readiness?.tools?.slang ? 'tool-on' : 'tool-off'}">
                  Slang Parser: {discoveryData?.readiness?.tools?.slang ? '✓ Available' : '○ Missing'}
                </span>
                <span class="tool-tag {discoveryData?.readiness?.tools?.z3 ? 'tool-on' : 'tool-off'}">
                  Z3 SMT Solver: {discoveryData?.readiness?.tools?.z3 ? '✓ Available' : '○ Missing'}
                </span>
                <span class="tool-tag {discoveryData?.readiness?.tools?.verilator ? 'tool-on' : 'tool-off'}">
                  Verilator: {discoveryData?.readiness?.tools?.verilator ? '✓ Available' : '○ Missing'}
                </span>
              </div>
            </div>

            <div class="quick-nav-actions" style="margin-top: 1.5rem;">
              <button class="btn btn-secondary" on:click={() => navigate(`/projects/${projectName}/modules`)}>
                📦 Inspect {dynamicModules.length} Discovered Modules
              </button>
            </div>
          </div>
        </div>
      </section>
    {/if}

    <!-- ================================================================= -->
    <!-- VIEW 3: DYNAMIC MODULE-WISE INSPECTION -->
    <!-- ================================================================= -->
    {#if activeView === 'modules'}
      <section class="modules-container">
        <div class="modules-header-card card glass">
          <div>
            <h2>Discovered Modules Inventory</h2>
            <p class="subtext">
              Dynamic module hierarchy and interface facts extracted from repository SystemVerilog/Verilog source code.
            </p>
          </div>
          <div class="filters-bar">
            <input type="text" placeholder="Search modules..." bind:value={moduleSearchText} class="search-input" />
            <select bind:value={moduleStatusFilter} class="filter-select">
              <option value="ALL">All Modules ({dynamicModules.length})</option>
              <option value="WITH_FINDINGS">With Findings</option>
              <option value="NOT_ANALYZED">Not Analyzed</option>
            </select>
          </div>
        </div>

        <div class="modules-grid-view">
          {#if filteredDynamicModules.length === 0}
            <div class="empty-state card glass" style="grid-column: 1 / -1;">
              <span class="empty-icon">📦</span>
              <p>No modules match your filter criteria.</p>
            </div>
          {:else}
            {#each filteredDynamicModules as mod}
              <div class="module-card card glass" on:click={() => openModuleDetail(mod.name)}>
                <div class="module-card-top">
                  <h4>{mod.name}</h4>
                  {#if mod.findings_count > 0}
                    <span class="badge badge-danger">Findings: {mod.findings_count}</span>
                  {:else}
                    <span class="badge badge-dim">Not analyzed</span>
                  {/if}
                </div>
                <div class="module-file-path" title={mod.file}>
                  📄 {mod.file} (Line {mod.line})
                </div>
                <div class="module-meta-chips">
                  <span class="mini-chip">Ports: {mod.ports_count || (mod.ports ? mod.ports.length : 0)}</span>
                  <span class="mini-chip">Instances: {mod.instances_count || (mod.instances ? mod.instances.length : 0)}</span>
                  {#if mod.clocks && mod.clocks.length > 0}
                    <span class="mini-chip clock-chip">⚡ Clocks: {mod.clocks.length}</span>
                  {/if}
                </div>
                <div class="module-card-footer">
                  <button class="btn btn-sm btn-secondary" on:click|stopPropagation={() => openModuleDetail(mod.name)}>
                    Inspect Interface
                  </button>
                </div>
              </div>
            {/each}
          {/if}
        </div>
      </section>
    {/if}

    <!-- ================================================================= -->
    <!-- VIEW 4: ANALYSIS CONFIGURATION & LIVE EXECUTION PIPELINE -->
    <!-- ================================================================= -->
    {#if activeView === 'analyze'}
      <section class="analyze-container">
        <!-- Configuration Card -->
        <div class="card glass config-card">
          <h2>Security Analysis Configuration</h2>
          <p class="subtext">Configure scope, formal verification engines, and dynamic validation options.</p>

          <div class="config-grid">
            <div class="config-group">
              <label>Target Repository:</label>
              <div class="readonly-path"><code>{designDir || 'Current Project Repository'}</code></div>
            </div>

            <div class="config-group">
              <label>Analysis Scope:</label>
              <div class="radio-row">
                <label class="radio-label">
                  <input type="radio" bind:group={analysisScope} value="entire" />
                  Entire Repository ({dynamicModules.length} Modules)
                </label>
                <label class="radio-label">
                  <input type="radio" bind:group={analysisScope} value="selected_modules" />
                  Selected Module
                </label>
              </div>
            </div>

            {#if analysisScope === 'selected_modules'}
              <div class="config-group">
                <label>Select Target Module:</label>
                <select class="module-select" on:change={(e) => selectedAnalysisModules = [e.target.value]}>
                  {#each dynamicModules as m}
                    <option value={m.name}>{m.name} ({m.file})</option>
                  {/each}
                </select>
              </div>
            {/if}

            <div class="config-group">
              <label>Analysis Types:</label>
              <div class="checkbox-grid">
                <label class="checkbox-label">
                  <input type="checkbox" bind:checked={analysisTypes.structural} />
                  Structural Security Analysis
                </label>
                <label class="checkbox-label">
                  <input type="checkbox" bind:checked={analysisTypes.data_control_flow} />
                  Data/Control-Flow Analysis
                </label>
                <label class="checkbox-label">
                  <input type="checkbox" bind:checked={analysisTypes.reachability} />
                  Z3 SMT Reachability Analysis
                </label>
                <label class="checkbox-label">
                  <input type="checkbox" bind:checked={analysisTypes.ai_assisted} />
                  AI-Assisted Reasoning
                </label>
                <label class="checkbox-label">
                  <input type="checkbox" bind:checked={analysisTypes.validation} />
                  Evidence & Witness Validation
                </label>
              </div>
            </div>

            <div class="config-group">
              <label>AI Provider Selection:</label>
              <select bind:value={selectedAIProvider} class="provider-select">
                <option value="automatic">Automatic Routing (Recommended)</option>
                {#each aiProvidersCatalog as p}
                  <option value={p.id}>{p.name} ({p.status})</option>
                {/each}
              </select>
            </div>
          </div>

          <div class="config-footer">
            <button class="btn btn-primary btn-lg" on:click={triggerStartAnalysis} disabled={startingAnalysis || analysisJob.status === 'RUNNING'}>
              {analysisJob.status === 'RUNNING' ? 'Analysis Running...' : '🚀 Start Analysis'}
            </button>
          </div>
        </div>

        <!-- Live Pipeline Execution Tracker -->
        <div class="card glass pipeline-card">
          <div class="pipeline-header">
            <div>
              <h3>Analysis Pipeline Execution</h3>
              <p class="subtext">Real-time execution status and stage transitions</p>
            </div>
            <div class="progress-pill">
              Overall Progress: <strong>{analysisJob.progress_pct || 0}%</strong>
            </div>
          </div>

          <!-- Progress Bar -->
          <div class="progress-bar-track">
            <div class="progress-bar-fill" style="width: {analysisJob.progress_pct || 0}%"></div>
          </div>

          <!-- Current Activity Box -->
          <div class="current-activity-box">
            <div class="activity-item">
              <span class="act-label">Current Stage:</span>
              <strong class="act-val highlight-val">{analysisJob.current_stage || 'Ready'}</strong>
            </div>
            {#if analysisJob.current_module}
              <div class="activity-item">
                <span class="act-label">Current Module:</span>
                <strong class="act-val">{analysisJob.current_module}</strong>
              </div>
            {/if}
            {#if analysisJob.current_file}
              <div class="activity-item">
                <span class="act-label">Current File:</span>
                <code class="act-val">{analysisJob.current_file}</code>
              </div>
            {/if}
          </div>

          <!-- Stage Stepper Cards -->
          <div class="stages-stepper">
            {#each analysisJob.stages as stg}
              <div class="stage-chip {stg.status.toLowerCase()}">
                <span class="stage-icon">
                  {#if stg.status === 'COMPLETED'}✓
                  {:else if stg.status === 'RUNNING'}●
                  {:else if stg.status === 'SKIPPED'}—
                  {:else}○{/if}
                </span>
                <span class="stage-name">{stg.name}</span>
              </div>
            {/each}
          </div>

          <!-- Completion Banner -->
          {#if analysisJob.status === 'COMPLETED'}
            <div class="alert alert-success" style="margin-top: 1.5rem; display: flex; justify-content: space-between; align-items: center;">
              <div>
                <strong>✓ Analysis Completed Successfully</strong>
                <p style="margin: 0.25rem 0 0 0;">Identified {analysisJob.findings_count || 0} findings. Detailed reports generated.</p>
              </div>
              <button class="btn btn-primary" on:click={() => navigate('/findings')}>
                🚨 View Findings ({analysisJob.findings_count || 0})
              </button>
            </div>
          {/if}

          <!-- Live Console Output -->
          <details class="console-accordion" open={analysisJob.status === 'RUNNING'}>
            <summary class="console-summary">Pipeline Execution Console Log ({analysisJob.logs.length} lines)</summary>
            <div class="terminal-log-viewer">
              {#each analysisJob.logs as log}
                <div class="log-line">{log}</div>
              {/each}
            </div>
          </details>
        </div>
      </section>
    {/if}

    <!-- ================================================================= -->
    <!-- VIEW 5: HUMAN-READABLE FINDINGS -->
    <!-- ================================================================= -->
    {#if activeView === 'findings'}
      <section class="findings-container">
        <!-- Summary Cards -->
        <div class="stats-grid findings-stats">
          <div class="stat-card card glass stat-danger">
            <span class="stat-number">{findingsList.filter(f => f.validation_status === 'VALIDATED' || f.status === 'CONFIRMED').length}</span>
            <span class="stat-label">Validated Vulnerabilities</span>
          </div>
          <div class="stat-card card glass stat-warning">
            <span class="stat-number">{findingsList.filter(f => f.validation_status === 'PARTIALLY_VALIDATED' || f.status === 'PROBABLE').length}</span>
            <span class="stat-label">Partially Validated</span>
          </div>
          <div class="stat-card card glass stat-dim">
            <span class="stat-number">{findingsList.filter(f => f.validation_status === 'UNCONFIRMED' || f.status === 'LEAD').length}</span>
            <span class="stat-label">Unconfirmed Leads</span>
          </div>
          <div class="stat-card card glass">
            <span class="stat-number">{findingsList.length}</span>
            <span class="stat-label">Total Security Findings</span>
          </div>
        </div>

        <!-- Filter Bar -->
        <div class="card glass filters-card">
          <div class="filter-row">
            <input type="text" placeholder="Search findings by title, file, module, or CWE..." bind:value={findingSearchText} class="search-input" style="flex: 2;" />
            <select bind:value={findingSeverityFilter} class="filter-select">
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
            <select bind:value={findingStatusFilter} class="filter-select">
              <option value="ALL">All Statuses</option>
              <option value="VALIDATED">Validated</option>
              <option value="PARTIALLY_VALIDATED">Partially Validated</option>
              <option value="UNCONFIRMED">Unconfirmed</option>
              <option value="REJECTED">Rejected</option>
            </select>
            <select bind:value={findingModuleFilter} class="filter-select">
              <option value="ALL">All Modules</option>
              {#each modulesForFindingsFilter as mod}
                <option value={mod}>{mod}</option>
              {/each}
            </select>
          </div>
        </div>

        {#if findingsLoading}
          <div class="loading-state"><span class="spinner"></span> Loading findings...</div>
        {:else if filteredFindings.length === 0}
          <div class="empty-state card glass">
            <span class="empty-icon">🛡️</span>
            <h3>No findings match the current filters.</h3>
            <p>Run a security analysis or adjust your filter selection above.</p>
          </div>
        {:else}
          <div class="findings-cards-list">
            {#each filteredFindings as f}
              <div class="finding-card card glass" on:click={() => openFindingModal(f)}>
                <div class="finding-card-header">
                  <div class="badges-row">
                    <span class="badge sev-badge sev-{f.severity ? f.severity.toLowerCase() : 'unknown'}">{f.severity || 'UNKNOWN'}</span>
                    <span class="badge val-badge val-{f.validation_status ? f.validation_status.toLowerCase() : (f.status ? f.status.toLowerCase() : 'detected')}">
                      {f.validation_status || f.status || 'DETECTED'}
                    </span>
                    <span class="cwe-pill">{f.cwe || f.weakness_class || 'CWE'}</span>
                  </div>
                  <span class="finding-id">{f.finding_id}</span>
                </div>

                <h3 class="finding-title">{f.human_title || f.title || `${f.weakness_class} in ${f.definition_id || f.file}`}</h3>

                <p class="finding-summary-text">
                  {f.what_is_wrong || 'Potential vulnerability condition identified in hardware access control or data flow.'}
                </p>

                <div class="finding-location-box">
                  <span class="loc-item"><strong>Module:</strong> {f.definition_id || f.module_name || f.module || 'unknown'}</span>
                  <span class="loc-item"><strong>File:</strong> <code>{f.file || f.file_path || f.source}</code></span>
                  <span class="loc-item"><strong>Line:</strong> {f.line_number || (f.line_range ? f.line_range[0] : 1)}</span>
                </div>

                <div class="finding-card-footer">
                  <span class="evidence-tag">Evidence: {f.evidence_summary?.reachability || 'Z3 Verified'}</span>
                  <button class="btn btn-sm btn-primary" on:click|stopPropagation={() => openFindingModal(f)}>
                    🔍 View Details & Evidence
                  </button>
                </div>
              </div>
            {/each}
          </div>
        {/if}
      </section>
    {/if}

    <!-- ================================================================= -->
    <!-- VIEW 6: REPORTS & EXPORTS -->
    <!-- ================================================================= -->
    {#if activeView === 'reports'}
      <section class="reports-container">
        <div class="card glass reports-hero-card">
          <h2>Security Analysis Reports & Artifacts</h2>
          <p class="subtext">
            Export machine-readable and executive audit reports for project {projectName || 'Active Repository'}.
          </p>

          <div class="report-metrics-row">
            <div class="rep-metric">
              <span class="val">{findingsList.length}</span>
              <span class="lbl">Total Findings</span>
            </div>
            <div class="rep-metric">
              <span class="val">{findingsList.filter(f => f.validation_status === 'VALIDATED' || f.status === 'CONFIRMED').length}</span>
              <span class="lbl">Validated Proofs</span>
            </div>
            <div class="rep-metric">
              <span class="val">{dynamicModules.length}</span>
              <span class="lbl">Modules Covered</span>
            </div>
          </div>

          <div class="report-actions-row">
            <a href="/reports/report.json" target="_blank" download="soc_security_report.json" class="btn btn-primary">
              📥 Download Machine JSON Report
            </a>
            <a href="/reports/report.html" target="_blank" download="soc_security_report.html" class="btn btn-secondary">
              📥 Download HTML Audit Report
            </a>
          </div>
        </div>

        <div class="card glass available-reports-card">
          <h3>Generated Workspace Reports</h3>
          {#if reportsList.length === 0}
            <p class="subtext">No historical reports found in workspace. Run an analysis to generate reports.</p>
          {:else}
            <div class="reports-table-wrap">
              <table class="simple-table">
                <thead>
                  <tr>
                    <th>Report File</th>
                    <th>Size</th>
                    <th>Created</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {#each reportsList as rep}
                    <tr>
                      <td><strong>{rep.filename || rep.name}</strong></td>
                      <td>{rep.size || 'N/A'}</td>
                      <td>{rep.modified || 'Recent'}</td>
                      <td>
                        <a href="/reports/{rep.filename || rep.name}" target="_blank" class="btn btn-sm btn-secondary">
                          View
                        </a>
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        </div>
      </section>
    {/if}

    <!-- ================================================================= -->
    <!-- VIEW 7: AI SETTINGS & PROVIDER CONFIGURATION -->
    <!-- ================================================================= -->
    {#if activeView === 'settings'}
      <section class="settings-container">
        <div class="card glass settings-header-card">
          <div class="header-split">
            <div>
              <h2>AI Provider & Security Configuration</h2>
              <p class="subtext">
                Manage AI reasoning providers, secure server-side API key storage, and dynamic model routing.
              </p>
            </div>
            <div class="security-shield-badge">
              🔒 Zero Embedded Keys • Server-Side Masking Only
            </div>
          </div>

          <div class="default-routing-box">
            <label>Default AI Provider Strategy:</label>
            <div class="routing-select-row">
              <select bind:value={aiDefaultProvider} class="provider-select" on:change={() => apiCall('/api/ai/providers', { provider: 'strategy', default_provider: aiDefaultProvider })}>
                <option value="automatic">Automatic (Select based on task capability & health)</option>
                {#each aiProvidersCatalog as p}
                  <option value={p.id}>{p.name}</option>
                {/each}
              </select>
              <span class="subtext">If AI is unavailable or unconfigured, deterministic analysis continues uninterrupted.</span>
            </div>
          </div>
        </div>

        <!-- Providers Grid -->
        <div class="providers-grid">
          {#each aiProvidersCatalog as p}
            <div class="provider-card card glass {p.status === 'Connected' ? 'connected-card' : ''}">
              <div class="provider-card-top">
                <h4>{p.name}</h4>
                {#if p.status === 'Connected'}
                  <span class="badge badge-success">● Connected</span>
                {:else}
                  <span class="badge badge-dim">○ Not configured</span>
                {/if}
              </div>

              <div class="provider-details">
                <div class="p-detail-item">
                  <span class="p-lbl">Default Model:</span>
                  <code>{p.default_model || 'Default'}</code>
                </div>
                <div class="p-detail-item">
                  <span class="p-lbl">API Key:</span>
                  <code class="masked-key">{p.masked_key || 'No key entered'}</code>
                </div>
                <div class="p-detail-item">
                  <span class="p-lbl">Endpoint:</span>
                  <span class="endpoint-txt">{p.endpoint || 'Standard HTTPS'}</span>
                </div>
              </div>

              <div class="provider-card-footer">
                <button class="btn btn-sm btn-primary" on:click={() => openEditProviderModal(p)}>
                  ⚙️ Configure Provider
                </button>
              </div>
            </div>
          {/each}
        </div>

        <!-- Cost & Usage Accounting Box -->
        <div class="card glass usage-accounting-card">
          <h3>AI Usage & Cost Accounting</h3>
          <div class="usage-stats-row">
            <div class="usage-stat">
              <span class="u-val">${aiUsageData?.spent_usd !== undefined ? aiUsageData.spent_usd.toFixed(4) : '0.0000'}</span>
              <span class="u-lbl">Total Estimated Spent</span>
            </div>
            <div class="usage-stat">
              <span class="u-val">{aiUsageData?.api_calls || 0}</span>
              <span class="u-lbl">Live API Calls</span>
            </div>
            <div class="usage-stat">
              <span class="u-val">{aiUsageData?.terminal_calls || 0}</span>
              <span class="u-lbl">Terminal Verification Calls</span>
            </div>
            <div class="usage-stat">
              <span class="u-val">{aiUsageData?.cache_hits || 0}</span>
              <span class="u-lbl">Cache Hits</span>
            </div>
          </div>
        </div>
      </section>
    {/if}
  </div>

  <!-- ================================================================= -->
  <!-- MODAL: DETAILED FINDING INSPECTOR & SOURCE VIEWER -->
  <!-- ================================================================= -->
  {#if selectedFindingModal}
    <div class="modal-backdrop" role="button" tabindex="0" on:click={() => selectedFindingModal = null} on:keydown={(e) => e.key === 'Escape' && (selectedFindingModal = null)}>
      <div class="modal card glass finding-detail-modal" role="dialog" aria-modal="true" on:click|stopPropagation on:keydown|stopPropagation>
        <div class="modal-header">
          <div>
            <div class="badges-row" style="margin-bottom: 0.4rem;">
              <span class="badge sev-badge sev-{selectedFindingModal.severity ? selectedFindingModal.severity.toLowerCase() : 'unknown'}">
                {selectedFindingModal.severity || 'UNKNOWN'}
              </span>
              <span class="badge val-badge val-{selectedFindingModal.validation_status ? selectedFindingModal.validation_status.toLowerCase() : 'detected'}">
                Status: {selectedFindingModal.validation_status || selectedFindingModal.status || 'DETECTED'}
              </span>
              <span class="cwe-pill">{selectedFindingModal.cwe || 'CWE'}</span>
            </div>
            <h2>{selectedFindingModal.human_title || selectedFindingModal.title}</h2>
          </div>
          <button class="btn-close" on:click={() => selectedFindingModal = null}>✕</button>
        </div>

        <div class="modal-body scrollable-modal-content">
          <!-- Location Details Box -->
          <div class="location-banner">
            <div class="loc-field">
              <span class="lbl">File:</span>
              <code>{selectedFindingModal.file || selectedFindingModal.file_path || selectedFindingModal.source}</code>
            </div>
            <div class="loc-field">
              <span class="lbl">Module:</span>
              <strong>{selectedFindingModal.definition_id || selectedFindingModal.module_name || selectedFindingModal.module}</strong>
            </div>
            <div class="loc-field">
              <span class="lbl">Line:</span>
              <strong>{selectedFindingModal.line_number || (selectedFindingModal.line_range ? selectedFindingModal.line_range[0] : 1)}</strong>
            </div>
            <button class="btn btn-sm btn-secondary" on:click={() => loadSourceSnippet(selectedFindingModal.file || selectedFindingModal.source, selectedFindingModal.line_number || (selectedFindingModal.line_range ? selectedFindingModal.line_range[0] : 1))}>
              {sourceSnippetVisible ? 'Hide Source' : '📄 View Source Code'}
            </button>
          </div>

          <!-- Live Source Code Snippet Viewer -->
          {#if sourceSnippetVisible}
            <div class="snippet-viewer-box">
              <div class="snippet-header">
                <span>Source Location Preview: <code>{sourceSnippet?.file || selectedFindingModal.file}</code></span>
                <span class="subtext">Highlighted Line: {selectedFindingModal.line_number || 1}</span>
              </div>
              {#if sourceSnippetLoading}
                <div class="snippet-loading"><span class="spinner"></span> Loading source snippet...</div>
              {:else if sourceSnippet?.error}
                <div class="alert alert-error">{sourceSnippet.error}</div>
              {:else if sourceSnippet?.lines}
                <div class="code-lines-container">
                  {#each sourceSnippet.lines as l}
                    <div class="code-line {l.highlight ? 'highlighted-line' : ''}">
                      <span class="line-num">{l.line_num}</span>
                      <pre class="line-text">{l.content}</pre>
                    </div>
                  {/each}
                </div>
              {/if}
            </div>
          {/if}

          <!-- What Happened Section -->
          <div class="detail-section">
            <h3>What is wrong?</h3>
            <p>{selectedFindingModal.what_is_wrong || 'An invalid or unconstrained hardware condition enables this state.'}</p>
          </div>

          <!-- Why It Matters Section -->
          <div class="detail-section">
            <h3>Why is this a security problem?</h3>
            <p>{selectedFindingModal.why_it_matters || 'Unauthorized actors could bypass hardware access protections.'}</p>
          </div>

          <!-- Attack Path Section -->
          <div class="detail-section">
            <h3>Attack Path</h3>
            <div class="attack-path-diagram">
              <pre>{selectedFindingModal.attack_path}</pre>
            </div>
          </div>

          <!-- Evidence & Reachability Section -->
          <div class="detail-section">
            <h3>Collected Evidence & Verification</h3>
            <div class="evidence-grid">
              <div class="ev-item">
                <span class="ev-lbl">Static Analysis:</span>
                <p>{selectedFindingModal.evidence_summary?.static || 'Target signal unguarded in assignment flow.'}</p>
              </div>
              <div class="ev-item">
                <span class="ev-lbl">Reachability (SMT Proof):</span>
                <p><strong>{selectedFindingModal.evidence_summary?.reachability || 'SAT (Z3 SMT Solver)'}</strong></p>
              </div>
              <div class="ev-item">
                <span class="ev-lbl">Witness Reproduction:</span>
                <p>{selectedFindingModal.evidence_summary?.dynamic || 'Witness generated'}</p>
              </div>
            </div>
          </div>

          <!-- How to Reproduce Section -->
          <div class="detail-section">
            <h3>How to Reproduce</h3>
            <ol class="repro-list">
              {#if selectedFindingModal.reproduction_steps && selectedFindingModal.reproduction_steps.length > 0}
                {#each selectedFindingModal.reproduction_steps as step}
                  <li>{step}</li>
                {/each}
              {:else}
                <li>1. Assert reset and initialize module interface.</li>
                <li>2. Drive target input bypass signal.</li>
                <li>3. Observe register state change while lock is active.</li>
              {/if}
            </ol>
          </div>

          <!-- Recommended Fix Section -->
          <div class="detail-section fix-section">
            <h3>Recommended Fix / Remediation</h3>
            <p><strong>Affected Block:</strong> <code>{selectedFindingModal.module_name || selectedFindingModal.definition_id}</code> at line {selectedFindingModal.line_number || 1}</p>
            <p class="fix-guidance">
              {selectedFindingModal.recommended_fix?.guidance || selectedFindingModal.recommended_fix || 'Ensure that write permissions require the lock signal to be strictly de-asserted.'}
            </p>
            {#if selectedFindingModal.recommended_fix?.side_effects}
              <p class="subtext"><em>Side Effects:</em> {selectedFindingModal.recommended_fix.side_effects}</p>
            {/if}
          </div>
        </div>

        <div class="modal-footer">
          {#if revalidateMessage}
            <span class="reval-msg">{revalidateMessage}</span>
          {/if}
          <button class="btn btn-secondary" on:click={() => triggerRevalidateFinding(selectedFindingModal.finding_id)} disabled={revalidating}>
            {revalidating ? 'Revalidating...' : '🔄 Revalidate Finding'}
          </button>
          <button class="btn btn-primary" on:click={() => selectedFindingModal = null}>
            Close
          </button>
        </div>
      </div>
    </div>
  {/if}

  <!-- ================================================================= -->
  <!-- MODAL: MODULE INSPECTOR -->
  <!-- ================================================================= -->
  {#if selectedModuleDetail}
    <div class="modal-backdrop" role="button" tabindex="0" on:click={() => selectedModuleDetail = null} on:keydown={(e) => e.key === 'Escape' && (selectedModuleDetail = null)}>
      <div class="modal card glass module-detail-modal" role="dialog" aria-modal="true" on:click|stopPropagation on:keydown|stopPropagation>
        <div class="modal-header">
          <div>
            <span class="section-tag">Module Inspector</span>
            <h2>{selectedModuleDetail.name}</h2>
            <p class="subtext">Source: <code>{selectedModuleDetail.file}</code> (Line {selectedModuleDetail.line})</p>
          </div>
          <button class="btn-close" on:click={() => selectedModuleDetail = null}>✕</button>
        </div>

        <div class="modal-body scrollable-modal-content">
          <!-- Ports Table -->
          <div class="detail-section">
            <h3>Module Ports ({selectedModuleDetail.ports ? selectedModuleDetail.ports.length : 0})</h3>
            {#if !selectedModuleDetail.ports || selectedModuleDetail.ports.length === 0}
              <p class="subtext">No ANSI ports parsed or top-level module.</p>
            {:else}
              <div class="ports-table-wrap">
                <table class="simple-table">
                  <thead>
                    <tr>
                      <th>Port Name</th>
                      <th>Direction</th>
                      <th>Width</th>
                      <th>Type</th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each selectedModuleDetail.ports as p}
                      <tr>
                        <td><strong>{p.name}</strong></td>
                        <td><span class="badge port-{p.direction}">{p.direction}</span></td>
                        <td><code>{p.width || '1'}</code></td>
                        <td>{p.port_type || 'logic'}</td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            {/if}
          </div>

          <!-- Clocks & Resets -->
          <div class="detail-section">
            <h3>Clocks & Resets</h3>
            <div class="clocks-resets-row">
              <div class="cr-box">
                <strong>Clocks ({selectedModuleDetail.clocks ? selectedModuleDetail.clocks.length : 0}):</strong>
                <div class="chip-container">
                  {#if selectedModuleDetail.clocks && selectedModuleDetail.clocks.length > 0}
                    {#each selectedModuleDetail.clocks as c}
                      <span class="chip chip-accent">⚡ {typeof c === 'string' ? c : c.signal_name}</span>
                    {/each}
                  {:else}
                    <span class="subtext">None identified</span>
                  {/if}
                </div>
              </div>
              <div class="cr-box">
                <strong>Resets ({selectedModuleDetail.resets ? selectedModuleDetail.resets.length : 0}):</strong>
                <div class="chip-container">
                  {#if selectedModuleDetail.resets && selectedModuleDetail.resets.length > 0}
                    {#each selectedModuleDetail.resets as r}
                      <span class="chip chip-dim">🔄 {typeof r === 'string' ? r : r.signal_name}</span>
                    {/each}
                  {:else}
                    <span class="subtext">None identified</span>
                  {/if}
                </div>
              </div>
            </div>
          </div>

          <!-- Child Instances -->
          <div class="detail-section">
            <h3>Instantiated Child Modules ({selectedModuleDetail.instances ? selectedModuleDetail.instances.length : 0})</h3>
            <div class="chip-container">
              {#if selectedModuleDetail.instances && selectedModuleDetail.instances.length > 0}
                {#each selectedModuleDetail.instances as inst}
                  <span class="chip chip-dim">📦 {inst}</span>
                {/each}
              {:else}
                <span class="subtext">No child module instances (leaf module)</span>
              {/if}
            </div>
          </div>
        </div>

        <div class="modal-footer">
          <button class="btn btn-secondary" on:click={() => {
            selectedAnalysisModules = [selectedModuleDetail.name];
            analysisScope = 'selected_modules';
            selectedModuleDetail = null;
            navigate(`/projects/${projectName}/analyze`);
          }}>
            Analyze This Module
          </button>
          <button class="btn btn-primary" on:click={() => selectedModuleDetail = null}>
            Close
          </button>
        </div>
      </div>
    </div>
  {/if}

  <!-- ================================================================= -->
  <!-- MODAL: AI PROVIDER CONFIGURATION -->
  <!-- ================================================================= -->
  {#if showAIConfigModal && editingProvider}
    <div class="modal-backdrop" role="button" tabindex="0" on:click={() => showAIConfigModal = false} on:keydown={(e) => e.key === 'Escape' && (showAIConfigModal = false)}>
      <div class="modal card glass ai-config-modal" role="dialog" aria-modal="true" on:click|stopPropagation on:keydown|stopPropagation>
        <div class="modal-header">
          <div>
            <span class="section-tag">AI Provider Configuration</span>
            <h2>{editingProvider.name}</h2>
          </div>
          <button class="btn-close" on:click={() => showAIConfigModal = false}>✕</button>
        </div>

        <div class="modal-body">
          <div class="form-group" style="margin-bottom: 1.25rem;">
            <label>API Key:</label>
            <div class="input-with-btn">
              {#if showApiKeyPlain}
                <input
                  type="text"
                  bind:value={editingApiKey}
                  placeholder={editingProvider.has_key ? `Current: ${editingProvider.masked_key}` : 'Enter API Key...'}
                  class="key-input"
                />
              {:else}
                <input
                  type="password"
                  bind:value={editingApiKey}
                  placeholder={editingProvider.has_key ? `Current: ${editingProvider.masked_key}` : 'Enter API Key...'}
                  class="key-input"
                />
              {/if}
              <button type="button" class="btn btn-secondary" on:click={() => showApiKeyPlain = !showApiKeyPlain}>
                {showApiKeyPlain ? 'Hide' : 'Show'}
              </button>
            </div>
            <span class="subtext" style="margin-top: 0.25rem;">
              Keys are stored securely server-side with restricted permissions (0600) and never logged or exposed in prompts.
            </span>
          </div>

          <div class="form-group" style="margin-bottom: 1.25rem;">
            <label>API Endpoint:</label>
            <input type="text" bind:value={editingEndpoint} placeholder="https://api.openai.com/v1" />
          </div>

          <div class="form-group" style="margin-bottom: 1.25rem;">
            <label>Model Selection:</label>
            {#if editingProvider.models && editingProvider.models.length > 0}
              <select bind:value={editingModel} class="provider-select">
                {#each editingProvider.models as m}
                  <option value={m}>{m}</option>
                {/each}
              </select>
            {:else}
              <input type="text" bind:value={editingModel} placeholder="default" />
            {/if}
          </div>

          {#if testConnectionResult}
            <div class="alert {testConnectionResult.status === 'ok' ? 'alert-success' : 'alert-error'}" style="margin-top: 1rem;">
              {testConnectionResult.message}
            </div>
          {/if}
        </div>

        <div class="modal-footer">
          <button class="btn btn-secondary" on:click={runTestConnection} disabled={testingConnection}>
            {testingConnection ? 'Testing...' : '⚡ Test Connection'}
          </button>
          <button class="btn btn-primary" on:click={saveProviderConfig} disabled={savingProvider}>
            {savingProvider ? 'Saving...' : 'Save Configuration'}
          </button>
        </div>
      </div>
    </div>
  {/if}
</main>

<style>
  :global(:root) {
    --bg-dark: #0a0e17;
    --card-bg: rgba(16, 24, 40, 0.65);
    --border-color: rgba(255, 255, 255, 0.08);
    --accent-blue: #0070f3;
    --accent-cyan: #00dfd8;
    --success-green: #00e676;
    --warning-amber: #ffab00;
    --danger-red: #ff3d00;
    --text-primary: #f0f3f6;
    --text-secondary: #8b949e;
  }

  :global(body) {
    margin: 0;
    padding: 0;
    background: var(--bg-dark);
    color: var(--text-primary);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
  }

  .dashboard-root {
    display: flex;
    flex-direction: column;
    min-height: 100vh;
  }

  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.8rem 1.5rem;
    background: rgba(10, 14, 23, 0.95);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border-color);
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    cursor: pointer;
  }

  .logo h1 {
    font-size: 1.15rem;
    margin: 0;
    font-weight: 700;
    background: linear-gradient(90deg, #fff, var(--accent-cyan));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  .pulse-dot {
    width: 10px;
    height: 10px;
    background: var(--accent-cyan);
    border-radius: 50%;
    box-shadow: 0 0 10px var(--accent-cyan);
  }

  .project-pill {
    background: rgba(0, 223, 216, 0.1);
    border: 1px solid rgba(0, 223, 216, 0.25);
    padding: 0.25rem 0.75rem;
    border-radius: 20px;
    font-size: 0.85rem;
    color: var(--accent-cyan);
  }

  .pill-label {
    color: var(--text-secondary);
    margin-right: 0.35rem;
  }

  .header-nav {
    display: flex;
    gap: 0.4rem;
    align-items: center;
  }

  .nav-btn {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    padding: 0.45rem 0.85rem;
    border-radius: 6px;
    font-size: 0.9rem;
    cursor: pointer;
    transition: all 0.15s ease;
  }

  .nav-btn:hover {
    color: var(--text-primary);
    background: rgba(255, 255, 255, 0.05);
  }

  .nav-btn.active {
    color: #fff;
    background: rgba(0, 112, 243, 0.2);
    border: 1px solid rgba(0, 112, 243, 0.4);
    font-weight: 600;
  }

  .status-indicator .badge {
    padding: 0.35rem 0.75rem;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
  }

  .badge.running {
    background: rgba(0, 230, 118, 0.15);
    color: var(--success-green);
    border: 1px solid var(--success-green);
  }

  .badge.idle {
    background: rgba(139, 148, 158, 0.15);
    color: var(--text-secondary);
    border: 1px solid var(--border-color);
  }

  .content-container {
    flex: 1;
    max-width: 1440px;
    margin: 0 auto;
    width: 100%;
    padding: 1.5rem;
    box-sizing: border-box;
  }

  .card.glass {
    background: var(--card-bg);
    backdrop-filter: blur(16px);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35);
  }

  /* HOME / HERO */
  .home-container {
    display: flex;
    flex-direction: column;
    gap: 2rem;
  }

  .hero-card {
    padding: 3rem 2.5rem;
    text-align: center;
    background: radial-gradient(circle at 50% 0%, rgba(0, 112, 243, 0.15), transparent 70%), var(--card-bg);
  }

  .hero-badge {
    display: inline-block;
    padding: 0.3rem 0.8rem;
    background: rgba(0, 223, 216, 0.1);
    color: var(--accent-cyan);
    border: 1px solid rgba(0, 223, 216, 0.3);
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 1rem;
  }

  .hero-card h2 {
    font-size: 2.5rem;
    margin: 0 0 1rem 0;
    font-weight: 800;
  }

  .hero-description {
    max-width: 760px;
    margin: 0 auto 2rem auto;
    font-size: 1.1rem;
    line-height: 1.6;
    color: var(--text-secondary);
  }

  .hero-cta-area {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1rem;
  }

  .or-divider {
    font-size: 0.85rem;
    color: var(--text-secondary);
  }

  .quick-path-row {
    width: 100%;
    max-width: 650px;
    display: flex;
    gap: 0.5rem;
  }

  .path-input {
    flex: 1;
    background: rgba(0, 0, 0, 0.4);
    border: 1px solid var(--border-color);
    color: #fff;
    padding: 0.65rem 1rem;
    border-radius: 6px;
    font-family: monospace;
  }

  .recent-projects-card {
    padding: 2rem;
  }

  .section-header {
    margin-bottom: 1.5rem;
  }

  .section-header h3 {
    margin: 0 0 0.35rem 0;
    font-size: 1.35rem;
  }

  .subtext {
    color: var(--text-secondary);
    font-size: 0.85rem;
  }

  .empty-state {
    text-align: center;
    padding: 3rem 1.5rem;
    color: var(--text-secondary);
  }

  .empty-icon {
    font-size: 3rem;
    display: block;
    margin-bottom: 0.75rem;
  }

  .projects-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
    gap: 1.25rem;
  }

  .project-card {
    padding: 1.25rem;
    cursor: pointer;
    transition: transform 0.15s ease, border-color 0.15s ease;
  }

  .project-card:hover {
    transform: translateY(-2px);
    border-color: rgba(0, 223, 216, 0.4);
  }

  .project-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.6rem;
  }

  .project-card-header h4 {
    margin: 0;
    font-size: 1.1rem;
  }

  .project-path {
    font-size: 0.8rem;
    color: var(--text-secondary);
    font-family: monospace;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    margin-bottom: 1rem;
  }

  .project-card-footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  /* BUTTONS & BADGES */
  .btn {
    padding: 0.55rem 1.15rem;
    border-radius: 6px;
    border: none;
    font-weight: 600;
    font-size: 0.9rem;
    cursor: pointer;
    transition: all 0.15s ease;
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
  }

  .btn-lg {
    padding: 0.85rem 2rem;
    font-size: 1.05rem;
  }

  .btn-sm {
    padding: 0.35rem 0.75rem;
    font-size: 0.8rem;
  }

  .btn-primary {
    background: linear-gradient(135deg, #0070f3, #00dfd8);
    color: #fff;
  }

  .btn-primary:hover:not(:disabled) {
    opacity: 0.92;
    transform: translateY(-1px);
  }

  .btn-secondary {
    background: rgba(255, 255, 255, 0.08);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
  }

  .btn-secondary:hover:not(:disabled) {
    background: rgba(255, 255, 255, 0.15);
  }

  .danger-text {
    color: var(--danger-red);
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .badge {
    padding: 0.25rem 0.6rem;
    border-radius: 12px;
    font-size: 0.72rem;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
  }

  .badge-success { background: rgba(0, 230, 118, 0.15); color: var(--success-green); }
  .badge-warning { background: rgba(255, 171, 0, 0.15); color: var(--warning-amber); }
  .badge-danger { background: rgba(255, 61, 0, 0.15); color: var(--danger-red); }
  .badge-info { background: rgba(0, 112, 243, 0.15); color: #60a5fa; }
  .badge-dim { background: rgba(139, 148, 158, 0.15); color: var(--text-secondary); }

  .big-badge {
    padding: 0.4rem 0.9rem;
    font-size: 0.85rem;
  }

  /* DISCOVERY VIEW */
  .discovery-container {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .discovery-header-card {
    padding: 1.75rem 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .section-tag {
    font-size: 0.75rem;
    text-transform: uppercase;
    color: var(--accent-cyan);
    font-weight: 700;
    letter-spacing: 1px;
  }

  .discovery-header-card h2 {
    margin: 0.25rem 0 0.5rem 0;
    font-size: 1.75rem;
  }

  .repo-path-display {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.85rem;
  }

  .repo-path-display code {
    background: rgba(0, 0, 0, 0.4);
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    color: #e2e8f0;
  }

  .btn-copy {
    background: transparent;
    border: none;
    cursor: pointer;
  }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem;
  }

  .stat-card {
    padding: 1.25rem;
    text-align: center;
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
  }

  .stat-number {
    font-size: 2rem;
    font-weight: 800;
    color: #fff;
  }

  .highlight-stat .stat-number {
    color: var(--accent-cyan);
  }

  .stat-label {
    font-size: 0.8rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .stat-danger .stat-number { color: var(--danger-red); }
  .stat-warning .stat-number { color: var(--warning-amber); }
  .stat-dim .stat-number { color: var(--text-secondary); }

  .details-split-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
  }

  .split-card {
    padding: 1.5rem;
  }

  .split-card h3 {
    margin-top: 0;
    font-size: 1.15rem;
  }

  .chip-container {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  .chip {
    padding: 0.35rem 0.75rem;
    border-radius: 20px;
    font-size: 0.8rem;
    font-weight: 600;
  }

  .chip-accent {
    background: rgba(0, 223, 216, 0.15);
    color: var(--accent-cyan);
    border: 1px solid rgba(0, 223, 216, 0.3);
  }

  .chip-dim {
    background: rgba(255, 255, 255, 0.05);
    color: var(--text-secondary);
    border: 1px solid var(--border-color);
  }

  .tools-status-row {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin-top: 0.75rem;
  }

  .tool-tag {
    font-size: 0.85rem;
    padding: 0.3rem 0.6rem;
    border-radius: 4px;
    font-weight: 600;
  }

  .tool-on { color: var(--success-green); background: rgba(0, 230, 118, 0.1); }
  .tool-off { color: var(--warning-amber); background: rgba(255, 171, 0, 0.1); }

  /* MODULES VIEW */
  .modules-container {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .modules-header-card {
    padding: 1.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .modules-header-card h2 {
    margin: 0 0 0.25rem 0;
  }

  .filters-bar {
    display: flex;
    gap: 0.75rem;
  }

  .search-input {
    background: rgba(0, 0, 0, 0.4);
    border: 1px solid var(--border-color);
    color: #fff;
    padding: 0.55rem 0.9rem;
    border-radius: 6px;
    min-width: 250px;
  }

  .filter-select {
    background: #111827;
    border: 1px solid var(--border-color);
    color: #fff;
    padding: 0.55rem 0.9rem;
    border-radius: 6px;
  }

  .modules-grid-view {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 1.25rem;
  }

  .module-card {
    padding: 1.25rem;
    cursor: pointer;
    transition: transform 0.15s ease, border-color 0.15s ease;
  }

  .module-card:hover {
    transform: translateY(-2px);
    border-color: rgba(0, 112, 243, 0.5);
  }

  .module-card-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
  }

  .module-card-top h4 {
    margin: 0;
    font-size: 1.05rem;
  }

  .module-file-path {
    font-size: 0.75rem;
    color: var(--text-secondary);
    font-family: monospace;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    margin-bottom: 0.75rem;
  }

  .module-meta-chips {
    display: flex;
    gap: 0.4rem;
    flex-wrap: wrap;
    margin-bottom: 1rem;
  }

  .mini-chip {
    font-size: 0.7rem;
    background: rgba(255, 255, 255, 0.05);
    padding: 0.2rem 0.45rem;
    border-radius: 4px;
    color: var(--text-secondary);
  }

  .clock-chip {
    color: var(--accent-cyan);
    background: rgba(0, 223, 216, 0.1);
  }

  /* ANALYZE VIEW & PIPELINE */
  .analyze-container {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .config-card, .pipeline-card {
    padding: 1.75rem 2rem;
  }

  .config-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
    margin: 1.5rem 0;
  }

  .config-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .config-group label {
    font-size: 0.85rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    font-weight: 700;
  }

  .readonly-path code {
    background: rgba(0, 0, 0, 0.4);
    padding: 0.45rem 0.75rem;
    border-radius: 6px;
    display: block;
    font-size: 0.85rem;
  }

  .radio-row {
    display: flex;
    gap: 1.25rem;
  }

  .radio-label, .checkbox-label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
    font-size: 0.9rem;
  }

  .checkbox-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.6rem;
  }

  .provider-select, .module-select {
    background: #111827;
    border: 1px solid var(--border-color);
    color: #fff;
    padding: 0.6rem;
    border-radius: 6px;
  }

  .pipeline-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.25rem;
  }

  .progress-pill {
    background: rgba(0, 112, 243, 0.15);
    border: 1px solid rgba(0, 112, 243, 0.3);
    padding: 0.35rem 0.85rem;
    border-radius: 20px;
    color: #60a5fa;
    font-size: 0.9rem;
  }

  .progress-bar-track {
    height: 8px;
    background: rgba(255, 255, 255, 0.08);
    border-radius: 4px;
    overflow: hidden;
    margin-bottom: 1.5rem;
  }

  .progress-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, #0070f3, #00dfd8);
    transition: width 0.4s ease;
  }

  .current-activity-box {
    display: flex;
    gap: 2rem;
    padding: 1rem 1.25rem;
    background: rgba(0, 0, 0, 0.3);
    border-radius: 8px;
    border: 1px solid var(--border-color);
    margin-bottom: 1.5rem;
  }

  .activity-item {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }

  .act-label {
    font-size: 0.72rem;
    color: var(--text-secondary);
    text-transform: uppercase;
  }

  .highlight-val {
    color: var(--accent-cyan);
  }

  .stages-stepper {
    display: flex;
    flex-wrap: wrap;
    gap: 0.6rem;
    margin-bottom: 1.5rem;
  }

  .stage-chip {
    padding: 0.45rem 0.85rem;
    border-radius: 6px;
    font-size: 0.82rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 0.4rem;
    border: 1px solid var(--border-color);
  }

  .stage-chip.completed {
    color: var(--success-green);
    background: rgba(0, 230, 118, 0.1);
    border-color: rgba(0, 230, 118, 0.3);
  }

  .stage-chip.running {
    color: var(--accent-cyan);
    background: rgba(0, 223, 216, 0.1);
    border-color: var(--accent-cyan);
    animation: pulse 1.5s infinite;
  }

  .stage-chip.pending {
    color: var(--text-secondary);
    background: rgba(255, 255, 255, 0.03);
  }

  .stage-chip.skipped {
    color: #64748b;
    background: transparent;
  }

  .terminal-log-viewer {
    background: #05080f;
    border: 1px solid var(--border-color);
    padding: 0.85rem;
    border-radius: 6px;
    font-family: monospace;
    font-size: 0.8rem;
    max-height: 250px;
    overflow-y: auto;
    color: #94a3b8;
  }

  .log-line {
    padding: 0.15rem 0;
  }

  /* FINDINGS VIEW */
  .findings-container {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .filters-card {
    padding: 1.25rem;
  }

  .filter-row {
    display: flex;
    gap: 0.85rem;
    flex-wrap: wrap;
  }

  .findings-cards-list {
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
  }

  .finding-card {
    padding: 1.5rem;
    cursor: pointer;
    transition: transform 0.15s ease, border-color 0.15s ease;
  }

  .finding-card:hover {
    transform: translateY(-2px);
    border-color: rgba(0, 223, 216, 0.4);
  }

  .finding-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.75rem;
  }

  .badges-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .sev-critical { background: rgba(255, 61, 0, 0.2); color: #ff3d00; border: 1px solid #ff3d00; }
  .sev-high { background: rgba(255, 171, 0, 0.2); color: #ffab00; border: 1px solid #ffab00; }
  .sev-medium { background: rgba(0, 112, 243, 0.2); color: #60a5fa; border: 1px solid #0070f3; }
  .sev-low { background: rgba(139, 148, 158, 0.2); color: #94a3b8; border: 1px solid #8b949e; }

  .val-validated { background: rgba(0, 230, 118, 0.15); color: var(--success-green); }
  .val-partially_validated { background: rgba(0, 112, 243, 0.15); color: #60a5fa; }
  .val-unconfirmed { background: rgba(139, 148, 158, 0.15); color: var(--text-secondary); }
  .val-rejected { background: rgba(255, 61, 0, 0.1); color: #f87171; }

  .cwe-pill {
    font-size: 0.72rem;
    background: rgba(255, 255, 255, 0.06);
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    font-family: monospace;
  }

  .finding-id {
    font-size: 0.75rem;
    color: var(--text-secondary);
    font-family: monospace;
  }

  .finding-title {
    margin: 0 0 0.6rem 0;
    font-size: 1.25rem;
  }

  .finding-summary-text {
    color: var(--text-secondary);
    font-size: 0.92rem;
    line-height: 1.5;
    margin: 0 0 1rem 0;
  }

  .finding-location-box {
    display: flex;
    gap: 1.5rem;
    padding: 0.65rem 0.9rem;
    background: rgba(0, 0, 0, 0.35);
    border-radius: 6px;
    font-size: 0.82rem;
    margin-bottom: 1rem;
    flex-wrap: wrap;
  }

  .finding-card-footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .evidence-tag {
    font-size: 0.8rem;
    color: var(--accent-cyan);
  }

  /* MODALS */
  .modal-backdrop {
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    background: rgba(0, 0, 0, 0.75);
    backdrop-filter: blur(8px);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 200;
    padding: 1.5rem;
    box-sizing: border-box;
  }

  .modal {
    max-width: 900px;
    width: 100%;
    max-height: 90vh;
    display: flex;
    flex-direction: column;
    padding: 0;
    overflow: hidden;
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    padding: 1.5rem 2rem;
    border-bottom: 1px solid var(--border-color);
  }

  .modal-header h2 {
    margin: 0;
    font-size: 1.45rem;
  }

  .btn-close {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    font-size: 1.5rem;
    cursor: pointer;
  }

  .scrollable-modal-content {
    padding: 1.5rem 2rem;
    overflow-y: auto;
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .modal-footer {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    gap: 1rem;
    padding: 1.25rem 2rem;
    border-top: 1px solid var(--border-color);
  }

  .location-banner {
    display: flex;
    gap: 1.5rem;
    align-items: center;
    padding: 0.85rem 1.25rem;
    background: rgba(0, 0, 0, 0.4);
    border-radius: 8px;
    flex-wrap: wrap;
  }

  .loc-field {
    display: flex;
    gap: 0.35rem;
    align-items: center;
    font-size: 0.85rem;
  }

  .detail-section h3 {
    margin: 0 0 0.6rem 0;
    font-size: 1.05rem;
    color: var(--accent-cyan);
  }

  .detail-section p {
    margin: 0;
    line-height: 1.6;
    color: #e2e8f0;
  }

  .attack-path-diagram pre {
    background: #05080f;
    padding: 1rem;
    border-radius: 6px;
    border: 1px solid var(--border-color);
    color: #38bdf8;
    font-size: 0.85rem;
    margin: 0;
  }

  .evidence-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }

  .ev-item {
    background: rgba(0, 0, 0, 0.25);
    padding: 0.75rem;
    border-radius: 6px;
    border: 1px solid var(--border-color);
  }

  .ev-lbl {
    font-size: 0.72rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    display: block;
    margin-bottom: 0.25rem;
  }

  .repro-list {
    margin: 0;
    padding-left: 1.25rem;
    line-height: 1.6;
    color: #e2e8f0;
  }

  .fix-section {
    background: rgba(0, 112, 243, 0.1);
    border: 1px solid rgba(0, 112, 243, 0.25);
    padding: 1rem;
    border-radius: 8px;
  }

  .fix-guidance {
    margin-top: 0.5rem !important;
  }

  /* CODE SNIPPET VIEWER */
  .snippet-viewer-box {
    background: #05080f;
    border: 1px solid rgba(0, 223, 216, 0.3);
    border-radius: 8px;
    overflow: hidden;
  }

  .snippet-header {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 1rem;
    background: rgba(255, 255, 255, 0.05);
    font-size: 0.8rem;
    border-bottom: 1px solid var(--border-color);
  }

  .code-lines-container {
    max-height: 320px;
    overflow-y: auto;
    font-family: monospace;
    font-size: 0.82rem;
  }

  .code-line {
    display: flex;
    padding: 0.15rem 0.5rem;
  }

  .highlighted-line {
    background: rgba(0, 223, 216, 0.2);
    border-left: 3px solid var(--accent-cyan);
  }

  .line-num {
    width: 45px;
    color: #64748b;
    user-select: none;
    text-align: right;
    padding-right: 1rem;
  }

  .line-text {
    margin: 0;
    color: #f1f5f9;
    white-space: pre-wrap;
  }

  /* AI SETTINGS */
  .settings-container {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .settings-header-card {
    padding: 1.75rem 2rem;
  }

  .header-split {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 1.5rem;
  }

  .security-shield-badge {
    background: rgba(0, 230, 118, 0.1);
    color: var(--success-green);
    border: 1px solid rgba(0, 230, 118, 0.3);
    padding: 0.4rem 0.8rem;
    border-radius: 20px;
    font-size: 0.8rem;
    font-weight: 600;
  }

  .default-routing-box {
    padding: 1rem 1.25rem;
    background: rgba(0, 0, 0, 0.3);
    border-radius: 8px;
    border: 1px solid var(--border-color);
  }

  .routing-select-row {
    display: flex;
    gap: 1rem;
    align-items: center;
    margin-top: 0.5rem;
  }

  .providers-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 1.25rem;
  }

  .provider-card {
    padding: 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .connected-card {
    border-color: rgba(0, 230, 118, 0.35);
  }

  .provider-card-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .provider-card-top h4 {
    margin: 0;
    font-size: 1.15rem;
  }

  .provider-details {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    font-size: 0.82rem;
  }

  .p-detail-item {
    display: flex;
    justify-content: space-between;
  }

  .p-lbl {
    color: var(--text-secondary);
  }

  .masked-key {
    color: var(--accent-cyan);
    font-family: monospace;
  }

  .endpoint-txt {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 170px;
  }

  .usage-accounting-card {
    padding: 1.75rem 2rem;
  }

  .usage-stats-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1.5rem;
    margin-top: 1rem;
  }

  .usage-stat {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    text-align: center;
  }

  .u-val {
    font-size: 1.75rem;
    font-weight: 800;
    color: var(--accent-cyan);
  }

  .u-lbl {
    font-size: 0.75rem;
    color: var(--text-secondary);
    text-transform: uppercase;
  }

  /* REPORTS */
  .reports-hero-card {
    padding: 2rem;
    text-align: center;
  }

  .report-metrics-row {
    display: flex;
    justify-content: center;
    gap: 3rem;
    margin: 1.5rem 0;
  }

  .rep-metric {
    display: flex;
    flex-direction: column;
  }

  .rep-metric .val {
    font-size: 2.2rem;
    font-weight: 800;
    color: #fff;
  }

  .rep-metric .lbl {
    font-size: 0.8rem;
    color: var(--text-secondary);
    text-transform: uppercase;
  }

  .report-actions-row {
    display: flex;
    justify-content: center;
    gap: 1rem;
  }

  .available-reports-card {
    padding: 1.75rem 2rem;
    margin-top: 1.5rem;
  }

  .simple-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.88rem;
  }

  .simple-table th, .simple-table td {
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--border-color);
    text-align: left;
  }

  .simple-table th {
    color: var(--text-secondary);
    font-weight: 600;
  }

  .alert {
    padding: 0.85rem 1.25rem;
    border-radius: 6px;
    font-size: 0.9rem;
  }

  .alert-success { background: rgba(0, 230, 118, 0.15); color: #86efac; border: 1px solid rgba(0, 230, 118, 0.3); }
  .alert-error { background: rgba(255, 61, 0, 0.15); color: #fca5a5; border: 1px solid rgba(255, 61, 0, 0.3); }
  .notice { background: rgba(0, 112, 243, 0.15); color: #93c5fd; border: 1px solid rgba(0, 112, 243, 0.3); }

  .toast-notice {
    position: fixed;
    bottom: 2rem;
    right: 2rem;
    background: rgba(0, 223, 216, 0.95);
    color: #000;
    font-weight: 700;
    padding: 0.75rem 1.5rem;
    border-radius: 8px;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
    z-index: 999;
  }

  .spinner {
    display: inline-block;
    width: 14px;
    height: 14px;
    border: 2px solid rgba(255, 255, 255, 0.2);
    border-top-color: var(--accent-cyan);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.6; }
  }
</style>
