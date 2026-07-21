<script lang="ts">
  import { onMount, afterUpdate } from 'svelte';
  import FolderTreeNode from './FolderTreeNode.svelte';

  // Types
  interface FolderNode {
    name: string;
    path: string;
    children: FolderNode[];
    isSuggestedExclusion: boolean;
  }
  interface ProjectConfig {
    project_name: string;
    design_dir: string;
    output_dir: string;
    exclude_patterns: string[];
    active_modules: string[];
  }

  interface PreScanResult {
    folders: string[];
    suggested_exclusions: string[];
    duplicates: Array<{
      module: string;
      paths: string[];
    }>;
    saved_exclusions?: string[] | null;
    saved_duplicates?: Record<string, string> | null;
  }

  interface ModuleStatus {
    name: string;
    status: 'VALIDATED' | 'PARTIAL' | 'FAILED' | 'UNVALIDATED';
    defined_in: string;
    errors: Record<string, string> | null;
    stubs?: string[];
  }

  interface RunStatus {
    running: boolean;
    progress: number;
    total_modules: number;
    completed_modules: number;
    fully_validated: number;
    partially_validated: number;
    failed: number;
    logs: string[];
  }

  // App State
  let step: 'setup' | 'config' | 'running' | 'results' = 'setup';
  let designDir: string = '/home/hackdac/opentitan';
  let projectName: string = 'opentitan';
  let configError: string = '';
  
  let preScanData: PreScanResult = {
    folders: [],
    suggested_exclusions: [],
    duplicates: []
  };

  let excludedFolders: Set<string> = new Set();
  let resolvedDuplicates: Record<string, string> = {}; // module -> selected path
  let activeProjectConfig: ProjectConfig | null = null;
  
  let runStatus: RunStatus = {
    running: false,
    progress: 0,
    total_modules: 0,
    completed_modules: 0,
    fully_validated: 0,
    partially_validated: 0,
    failed: 0,
    logs: []
  };

  let modulesList: ModuleStatus[] = [];
  let filterText: string = '';
  let statusFilter: string = 'ALL';
  let showLaunchModal: boolean = false;
  let selectedModuleForDetail: ModuleStatus | null = null;

  let folderTree: FolderNode[] = [];
  let expandedNodes: Set<string> = new Set();
  let hideUnselected: boolean = false;
  let initialExclusions: Set<string> = new Set();
  let initialDuplicates: Record<string, string> = {};

  // Phase navigation and Phase 0.3 Context Viewer state
  let activePhase: 'phase-0.1-0.2' | 'phase-0.3' | 'phase-0.4' | 'phase-1' | 'phase-2' | 'phase-3' = 'phase-0.1-0.2';
  let contextData: any = null;
  let selectedContextModule: string = '';
  let contextSubTab: 'hierarchy' | 'secrets' | 'trust' = 'hierarchy';
  let flatHierarchy: Array<{ name: string; instName: string; level: number }> = [];

  let synthesisStatus: { synthesis_running: boolean; synthesis_status?: string; synthesis_logs?: string[]; modules: Array<{ name: string; status: string; warning_count: number; error_count: number; risk_level: string }> } = { synthesis_running: false, synthesis_status: 'idle', synthesis_logs: [], modules: [] };
  let selectedSynthesisModule: string = '';
  let selectedSynthesisDetail: any = null;
  let synthesisStatusInterval: any = null;
  let showInternalModules: boolean = false;

  let synthConfig = {
    top_module: 'chip_earlgrey_asic',
    fusesoc_cores_root: '',
    fusesoc_core_name: '',
    run_slang_elab_check: true,
    auto_generate_stubs: true,
    max_stub_retries: 3,
    escalate_to_ai_on_failure: true
  };

  let selectedConsoleLogTab: 'validation' | 'repair' = 'validation';
  $: if (runStatus && runStatus.current_stream_type) {
    if (runStatus.running) {
      selectedConsoleLogTab = runStatus.current_stream_type as any;
    }
  }
  $: logsToDisplay = (selectedConsoleLogTab === 'repair') 
    ? (runStatus.repair_logs || []) 
    : (runStatus.validation_logs || runStatus.logs || []);

  function computeFlatHierarchy(hierarchyObj: any) {
    const result: Array<{ name: string; instName: string; level: number }> = [];
    
    function traverse(node: any, level = 0) {
      if (!node) return;
      const name = node.module_name || node.name || "Unknown";
      const instName = node.instance_name || "";
      result.push({ name, instName, level });
      if (node.children && Array.isArray(node.children)) {
        node.children.forEach((child: any) => traverse(child, level + 1));
      }
    }

    if (hierarchyObj && typeof hierarchyObj === 'object') {
      if (hierarchyObj.module_name || hierarchyObj.name) {
        traverse(hierarchyObj);
      } else {
        Object.values(hierarchyObj).forEach((tree: any) => traverse(tree));
      }
    }
    flatHierarchy = result;
  }

  async function fetchContext() {
    try {
      const data = await apiCall('/api/context');
      contextData = data;
      if (contextData && contextData.module_hierarchy) {
        computeFlatHierarchy(contextData.module_hierarchy);
      }
    } catch (e) {
      console.error("Failed to fetch context:", e);
    }
  }

  let selectedSynthesisConsoleTab: string = 'general';
  let activeModuleLogText: string = '';
  let activeModuleLogLoading: boolean = false;

  async function pausePipeline() {
    try {
      await apiCall('/api/pipeline/pause');
      pollStatus();
    } catch (e) {
      console.error("Failed to pause pipeline:", e);
    }
  }

  async function resumePipeline() {
    try {
      await apiCall('/api/pipeline/resume');
      pollStatus();
    } catch (e) {
      console.error("Failed to resume pipeline:", e);
    }
  }

  async function abortPipeline() {
    try {
      await apiCall('/api/pipeline/abort');
      step = 'config';
      pollStatus();
    } catch (e) {
      console.error("Failed to abort pipeline:", e);
    }
  }

  async function pauseSynthesis() {
    try {
      await apiCall('/api/synthesis/pause');
      fetchSynthesisStatus();
    } catch (e) {
      console.error("Failed to pause synthesis:", e);
    }
  }

  async function resumeSynthesis() {
    try {
      await apiCall('/api/synthesis/resume');
      fetchSynthesisStatus();
    } catch (e) {
      console.error("Failed to resume synthesis:", e);
    }
  }

  async function abortSynthesis() {
    try {
      await apiCall('/api/synthesis/abort');
      fetchSynthesisStatus();
    } catch (e) {
      console.error("Failed to abort synthesis:", e);
    }
  }

  async function selectSynthesisModuleConsole(moduleName: string) {
    selectedSynthesisConsoleTab = moduleName;
    activeModuleLogLoading = true;
    try {
      const data = await apiCall(`/api/synthesis/module/${moduleName}`);
      activeModuleLogText = data.log || '';
    } catch (e) {
      console.error(e);
      activeModuleLogText = 'Failed to load log.';
    } finally {
      activeModuleLogLoading = false;
    }
  }

  async function fetchSynthesisStatus() {
    try {
      const data = await apiCall('/api/synthesis/status');
      if (data) {
        synthesisStatus = data;
      }
    } catch (e) {
      console.error("Failed to fetch synthesis status:", e);
    }
  }

  async function startSynthesis() {
    try {
      selectedSynthesisConsoleTab = 'general';
      synthesisStatus = {
        ...synthesisStatus,
        synthesis_running: true,
        synthesis_status: 'running',
        synthesis_logs: ["Launching Yosys Synthesis Pipeline..."]
      };
      await apiCall('/api/synthesis/run', synthConfig);
      fetchSynthesisStatus();
    } catch (e) {
      console.error("Failed to start synthesis:", e);
      synthesisStatus = {
        ...synthesisStatus,
        synthesis_running: false,
        synthesis_status: 'failed',
        synthesis_logs: ["Failed to start synthesis: " + (e.message || e)]
      };
    }
  }

  let autodetectStatus: string = '';
  async function autodetectFusesoc() {
    if (!synthConfig.top_module) {
      autodetectStatus = 'Please enter a Top Module Name first.';
      setTimeout(() => autodetectStatus = '', 3000);
      return;
    }
    autodetectStatus = 'Detecting...';
    try {
      const res = await apiCall('/api/synthesis/autodetect_fusesoc', { top_module: synthConfig.top_module });
      if (res && res.fusesoc_core_name) {
        synthConfig.fusesoc_cores_root = res.fusesoc_cores_root || '';
        synthConfig.fusesoc_core_name = res.fusesoc_core_name;
        autodetectStatus = 'Detected!';
      } else {
        autodetectStatus = 'Failed to detect.';
      }
    } catch (e) {
      autodetectStatus = 'Failed to detect.';
    }
    setTimeout(() => autodetectStatus = '', 3000);
  }

  async function fetchSynthesisModuleDetail(moduleName: string) {
    try {
      selectedSynthesisModule = moduleName;
      const data = await apiCall(`/api/synthesis/module/${moduleName}`);
      selectedSynthesisDetail = data;
    } catch (e) {
      console.error("Failed to fetch synthesis module detail:", e);
    }
  }

  function toggleHideUnselected() {
    hideUnselected = !hideUnselected;
    if (hideUnselected) {
      autoExpandTree();
    }
  }

  function buildFolderTree(folders: string[], suggestedExclusions: string[]): FolderNode[] {
    const rootNodes: FolderNode[] = [];
    const nodeMap: Record<string, FolderNode> = {};
    const sortedFolders = [...folders].sort((a, b) => a.localeCompare(b));

    for (const f of sortedFolders) {
      if (f === "") continue;
      const parts = f.split('/');
      let currentPath = "";
      
      for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        const parentPath = currentPath;
        currentPath = currentPath ? `${currentPath}/${part}` : part;
        
        if (!nodeMap[currentPath]) {
          const node: FolderNode = {
            name: part,
            path: currentPath,
            children: [],
            isSuggestedExclusion: suggestedExclusions.includes(currentPath)
          };
          nodeMap[currentPath] = node;
          
          if (i === 0) {
            rootNodes.push(node);
          } else {
            const parentNode = nodeMap[parentPath];
            if (parentNode) {
              parentNode.children.push(node);
            }
          }
        }
      }
    }
    return rootNodes;
  }

  function autoExpandTree() {
    const newExpanded = new Set<string>();
    
    const analyzeNode = (node: FolderNode): { hasSelected: boolean; hasExcluded: boolean } => {
      let isSelected = !excludedFolders.has(node.path);
      let hasSelected = isSelected;
      let hasExcluded = !isSelected;
      
      for (const child of node.children) {
        const res = analyzeNode(child);
        if (res.hasSelected) hasSelected = true;
        if (res.hasExcluded) hasExcluded = true;
      }
      
      if (hasSelected && hasExcluded) {
        newExpanded.add(node.path);
      }
      
      return { hasSelected, hasExcluded };
    };
    
    folderTree.forEach(node => analyzeNode(node));
    expandedNodes = newExpanded;
  }

  function handleTreeCheckToggle(event: CustomEvent<{ node: FolderNode; checked: boolean }>) {
    const { node, checked } = event.detail;
    
    const walk = (n: FolderNode) => {
      if (checked) {
        excludedFolders.delete(n.path);
      } else {
        excludedFolders.add(n.path);
      }
      n.children.forEach(walk);
    };
    walk(node);
    excludedFolders = excludedFolders; // trigger reactivity
  }

  function handleTreeExpandToggle(event: CustomEvent<{ path: string }>) {
    const { path } = event.detail;
    if (expandedNodes.has(path)) {
      expandedNodes.delete(path);
    } else {
      expandedNodes.add(path);
    }
    expandedNodes = expandedNodes; // trigger reactivity
  }

  // Helper to call backend APIs
  async function apiCall(endpoint: string, payload?: any) {
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload ? JSON.stringify(payload) : undefined
      });
      return await response.json();
    } catch (e) {
      console.error(e);
      throw e;
    }
  }

  async function handlePreScan() {
    configError = '';
    try {
      const res = await apiCall('/api/scan', { design_dir: designDir, project_name: projectName });
      if (res.error) {
        configError = res.error;
        return;
      }
      preScanData = res;
      // Pre-populate exclusions
      if (preScanData.saved_exclusions) {
        excludedFolders = new Set(preScanData.saved_exclusions);
        initialExclusions = new Set(preScanData.saved_exclusions);
      } else {
        excludedFolders = new Set(preScanData.suggested_exclusions);
        initialExclusions = new Set(preScanData.suggested_exclusions);
      }
      // Pre-populate duplicate choices
      if (preScanData.saved_duplicates) {
        resolvedDuplicates = { ...preScanData.saved_duplicates };
        initialDuplicates = { ...preScanData.saved_duplicates };
      } else {
        resolvedDuplicates = {};
        preScanData.duplicates.forEach(d => {
          resolvedDuplicates[d.module] = d.paths[0];
        });
        initialDuplicates = { ...resolvedDuplicates };
      }
      folderTree = buildFolderTree(preScanData.folders, preScanData.suggested_exclusions);
      autoExpandTree();
      step = 'config';
    } catch (e) {
      configError = 'Failed to scan directory. Make sure backend is running.';
    }
  }

  function toggleFolder(folder: string) {
    if (excludedFolders.has(folder)) {
      excludedFolders.delete(folder);
    } else {
      excludedFolders.add(folder);
    }
    excludedFolders = excludedFolders; // Trigger svelte reactivity
  }

  let saveConfigStatus: string = '';
  async function handleSaveConfigOnly() {
    saveConfigStatus = 'Saving...';
    try {
      const configPayload: ProjectConfig = {
        project_name: projectName,
        design_dir: designDir,
        output_dir: `workspace/${projectName}_artifacts`,
        exclude_patterns: Array.from(excludedFolders),
        active_modules: []
      };
      
      await apiCall('/api/config/save', {
        config: configPayload,
        resolved_duplicates: resolvedDuplicates
      });
      saveConfigStatus = 'Saved successfully!';
      setTimeout(() => {
        saveConfigStatus = '';
      }, 3000);
    } catch (e) {
      saveConfigStatus = 'Failed to save configuration';
      setTimeout(() => {
        saveConfigStatus = '';
      }, 4000);
    }
  }

  function handleRestoreConfig() {
    excludedFolders = new Set(initialExclusions);
    resolvedDuplicates = { ...initialDuplicates };
    autoExpandTree();
  }

  let fileInput: HTMLInputElement;

  function triggerFilePicker() {
    if (fileInput) {
      fileInput.click();
    }
  }

  function handleFileLoad(event: Event) {
    const target = event.target as HTMLInputElement;
    const file = target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const parsed = JSON.parse(e.target?.result as string);
        let configData = parsed;
        let resolvedDups = {};

        if (parsed.config) {
          configData = parsed.config;
          resolvedDups = parsed.resolved_duplicates || {};
        }

        const excludePatterns = configData.exclude_patterns || [];
        const newExclusions = new Set<string>();

        preScanData.folders.forEach(f => {
          const fSlash = `/${f}/`;
          let isExcl = false;
          for (const pat of excludePatterns) {
            if (pat === f || fSlash.includes(pat) || f.includes(pat)) {
              isExcl = true;
              break;
            }
          }
          if (isExcl) {
            newExclusions.add(f);
          }
        });

        excludedFolders = newExclusions;
        resolvedDuplicates = resolvedDups;
        autoExpandTree();

        saveConfigStatus = 'Configuration loaded!';
        setTimeout(() => {
          saveConfigStatus = '';
        }, 3000);
      } catch (err) {
        saveConfigStatus = 'Invalid JSON config file';
        setTimeout(() => {
          saveConfigStatus = '';
        }, 4000);
      }
    };
    reader.readAsText(file);
    target.value = '';
  }

  async function handleStartRun() {
    if (runStatus.completed_modules > 0) {
      showLaunchModal = true;
      return;
    }
    await confirmCleanRun();
  }

  async function confirmCleanRun() {
    showLaunchModal = false;
    try {
      const configPayload: ProjectConfig = {
        project_name: projectName,
        design_dir: designDir,
        output_dir: `workspace/${projectName}_artifacts`,
        exclude_patterns: Array.from(excludedFolders),
        active_modules: [] // Will be populated by backend scan
      };
      
      // Save duplicate overrides config
      await apiCall('/api/config/save', {
        config: configPayload,
        resolved_duplicates: resolvedDuplicates
      });
      
      // Trigger execution
      runStatus = {
        running: true,
        progress: 0,
        total_modules: 0,
        completed_modules: 0,
        fully_validated: 0,
        partially_validated: 0,
        failed: 0,
        logs: ["Clearing old workspace and restarting pipeline..."],
        validation_logs: ["Clearing old workspace and restarting pipeline..."],
        repair_logs: [],
        synthesis_logs: []
      };
      modulesList = [];
      synthesisStatus = {
        synthesis_running: false,
        synthesis_status: 'idle',
        synthesis_logs: [],
        modules: []
      };
      proceedStatus = '';
      saveConfigStatus = '';
      configError = '';

      await apiCall('/api/run', { clean: true, project_name: projectName });
      
      step = 'running';
      pollStatus();
    } catch (e) {
      configError = 'Failed to launch verification run.';
    }
  }

  async function handleReRun() {
    try {
      // Trigger execution with clean=true
      runStatus = {
        running: true,
        progress: 0,
        total_modules: 0,
        completed_modules: 0,
        fully_validated: 0,
        partially_validated: 0,
        failed: 0,
        logs: ["Clearing workspace and restarting pipeline..."],
        validation_logs: ["Clearing workspace and restarting pipeline..."],
        repair_logs: [],
        synthesis_logs: []
      };
      modulesList = [];
      synthesisStatus = {
        synthesis_running: false,
        synthesis_status: 'idle',
        synthesis_logs: [],
        modules: []
      };
      proceedStatus = '';
      saveConfigStatus = '';
      configError = '';

      await apiCall('/api/run', { clean: true, project_name: projectName });
      
      step = 'running';
      pollStatus();
    } catch (e) {
      configError = 'Failed to launch clean verification run.';
    }
  }

  async function pollStatus() {
    try {
      const res = await fetch('/api/status');
      const data = await res.json();
      runStatus = data;
      modulesList = data.modules || [];
      if (runStatus.running) {
        step = 'running';
        setTimeout(pollStatus, 1500);
      } else {
        if (step === 'running') {
          step = 'results';
        }
      }
    } catch (e) {
      if (runStatus.running || step === 'running') {
        setTimeout(pollStatus, 3000);
      }
    }
  }

  // Persist config fields, current step and active phase in localStorage to handle refreshes
  $: if (typeof window !== 'undefined') {
    localStorage.setItem('projectName', projectName);
    localStorage.setItem('designDir', designDir);
    localStorage.setItem('step', step);
    localStorage.setItem('activePhase', activePhase);
  }

  $: if (step === 'results') {
    fetchContext();
  }

  onMount(() => {
    // Recover state from localStorage
    const savedProjectName = localStorage.getItem('projectName');
    const savedDesignDir = localStorage.getItem('designDir');
    const savedStep = localStorage.getItem('step');
    const savedActivePhase = localStorage.getItem('activePhase');
    if (savedProjectName) projectName = savedProjectName;
    if (savedDesignDir) designDir = savedDesignDir;
    if (savedStep && (savedStep === 'config' || savedStep === 'results' || savedStep === 'running')) {
      step = savedStep as any;
    }
    if (savedActivePhase) {
      activePhase = savedActivePhase as any;
    }
    
    // Check if a run is already active (overrides to 'running' if true)
    pollStatus();

    // Fetch and continuously update synthesis status in the background
    fetchSynthesisStatus();
    synthesisStatusInterval = setInterval(fetchSynthesisStatus, 1500);
  });

  let isRepairing = false;
  async function handleRepair() {
    try {
      isRepairing = true;
      runStatus = {
        running: true,
        progress: 0,
        total_modules: 0,
        completed_modules: 0,
        fully_validated: 0,
        partially_validated: 0,
        failed: 0,
        logs: ["Launching interactive Failure Repairer..."],
        validation_logs: [],
        repair_logs: ["Launching interactive Failure Repairer..."],
        synthesis_logs: []
      };
      modulesList = [];
      const res = await apiCall('/api/repair');
      if (res && res.detail) {
        runStatus = {
          ...runStatus,
          running: false,
          repair_logs: [res.detail]
        };
        step = 'results';
        selectedConsoleLogTab = 'repair';
        return;
      }
      step = 'running';
      pollStatus();
    } catch (e) {
      runStatus = {
        ...runStatus,
        running: false,
        repair_logs: [e.message || e || "API configuration not found. Configure an API key before running AI Repair."]
      };
      step = 'results';
      selectedConsoleLogTab = 'repair';
    } finally {
      isRepairing = false;
    }
  }

  let isProceeding = false;
  let proceedStatus = '';
  async function handleProceed() {
    try {
      isProceeding = true;
      proceedStatus = 'Registering active modules...';
      const res = await apiCall('/api/proceed');
      if (res.status === 'success') {
        proceedStatus = `Successfully proceeded with ${res.active_modules.length} modules!`;
        setTimeout(() => {
          proceedStatus = '';
        }, 5000);
      }
    } catch (e) {
      proceedStatus = 'Failed to proceed.';
      setTimeout(() => {
        proceedStatus = '';
      }, 5000);
    } finally {
      isProceeding = false;
    }
  }

  let consoleInputText = '';
  async function handleConsoleInputSubmit() {
    if (!consoleInputText.trim()) return;
    try {
      const text = consoleInputText.trim();
      consoleInputText = '';
      await apiCall('/api/input', { input_text: text });
    } catch (e) {
      console.error('Failed to send console input:', e);
    }
  }

  $: filteredModules = modulesList.filter(m => {
    const matchesSearch = m.name.toLowerCase().includes(filterText.toLowerCase());
    const matchesStatus = statusFilter === 'ALL' || m.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  let consoleElement: HTMLElement;

  afterUpdate(() => {
    if (consoleElement) {
      consoleElement.scrollTop = consoleElement.scrollHeight;
    }
  });
</script>

<main class="dashboard-root">
  <!-- Top Bar -->
  <header class="header">
    <div class="logo">
      <span class="pulse-dot"></span>
      <h1>SoC Security Pipeline Analyzer</h1>
    </div>
    <div class="status-indicator">
      {#if runStatus.running}
        <span class="badge running">Orchestrator Executing</span>
      {:else}
        <span class="badge idle">Orchestrator Idle</span>
      {/if}
    </div>
  </header>

  <div class="content-container">
    <!-- SETUP STEP -->
    {#if step === 'setup'}
      <section class="card glass">
        {#if runStatus.completed_modules > 0}
          <div class="existing-run-alert">
            <div class="alert-content">
              <strong>📬 Existing Validation Run Detected</strong>
              <p>We found {runStatus.completed_modules} completed modules for project "{projectName}" on disk.</p>
            </div>
            <div class="alert-actions">
              <button class="btn btn-secondary btn-sm" on:click={() => { step = 'results'; activePhase = 'phase-0.1-0.2'; }}>Load Previous Results</button>
            </div>
          </div>
        {/if}

        <h2>Ingest SoC Design Project</h2>
        <p class="subtitle">Specify the root directory of your SystemVerilog/Verilog hardware project to initialize static discovery.</p>
        
        <div class="form-group">
          <label for="project-name">Project Name</label>
          <input type="text" id="project-name" bind:value={projectName} placeholder="e.g. opentitan" />
        </div>

        <div class="form-group">
          <label for="design-dir">Design Root Directory</label>
          <input type="text" id="design-dir" bind:value={designDir} placeholder="e.g. /home/hackdac/opentitan" />
        </div>

        {#if configError}
          <div class="alert error">{configError}</div>
        {/if}

        <button class="btn btn-primary" on:click={handlePreScan}>Discover Assets & Exclusions</button>
      </section>
    {:else}
      <!-- SPLIT SIDEBAR LAYOUT -->
      <div class="dashboard-layout">
        <!-- Sidebar Navigation -->
        <aside class="sidebar">
          <div class="sidebar-section">
            <h3>Phase 0: Validation & Setup</h3>
            <button 
              class="sidebar-item {activePhase === 'phase-0.1-0.2' ? 'active' : ''}" 
              on:click={() => activePhase = 'phase-0.1-0.2'}
            >
              <span class="icon">🔍</span> Validation & Repair
            </button>
            <button 
              class="sidebar-item {activePhase === 'phase-0.3' ? 'active' : ''}" 
              on:click={() => { activePhase = 'phase-0.3'; fetchContext(); }}
              disabled={step === 'config'}
              title={step === 'config' ? 'Complete validation first to unlock' : ''}
            >
              <span class="icon">🌳</span> Design Context (Phase 0.3)
            </button>
            <button 
              class="sidebar-item {activePhase === 'phase-0.4' ? 'active' : ''}" 
              on:click={() => { activePhase = 'phase-0.4'; fetchSynthesisStatus(); }}
              disabled={step === 'config'}
              title={step === 'config' ? 'Complete validation first to unlock' : ''}
            >
              <span class="icon">⚙️</span> Shared Synthesis (Phase 0.4)
            </button>
          </div>

          <div class="sidebar-section">
            <h3>Phase 1-3: Auditing & Proofs</h3>
            <button 
              class="sidebar-item {activePhase === 'phase-1' ? 'active' : ''}" 
              on:click={() => activePhase = 'phase-1'}
            >
              <span class="icon">🤖</span> Worker Static Audits <span class="badge-lock">🔒</span>
            </button>
            <button 
              class="sidebar-item {activePhase === 'phase-2' ? 'active' : ''}" 
              on:click={() => activePhase = 'phase-2'}
            >
              <span class="icon">📊</span> Waveform Analysis <span class="badge-lock">🔒</span>
            </button>
            <button 
              class="sidebar-item {activePhase === 'phase-3' ? 'active' : ''}" 
              on:click={() => activePhase = 'phase-3'}
            >
              <span class="icon">🛡️</span> Formal Security Proofs <span class="badge-lock">🔒</span>
            </button>
          </div>

          <div class="sidebar-footer">
            <button class="btn btn-secondary btn-sm w-100" on:click={() => { step = 'setup'; activePhase = 'phase-0.1-0.2'; }}>
              ← Change Project
            </button>
          </div>
        </aside>

        <!-- Main Workspace -->
        <div class="main-workspace">
          {#if activePhase === 'phase-0.1-0.2'}
            <!-- CONFIGURATION STEP -->
            {#if step === 'config'}
              <div class="config-grid">
                <!-- Exclusion Panel -->
                <section class="card glass scrollable">
                  <div class="panel-header-row">
                    <h2>Directory Selection</h2>
                    <button 
                      type="button"
                      class="btn btn-secondary btn-sm" 
                      on:click={toggleHideUnselected} 
                      title="Toggle collapse / hide of unselected folders"
                    >
                      {hideUnselected ? "Show All Folders" : "Collapse Unselected"}
                    </button>
                  </div>
                  <p class="subtitle">Check the folders to include in analysis. Simulation, verification and testbench folders are unchecked by default to save token costs. Unselected folders will be collapsed and hidden when you click "Collapse Unselected".</p>
                  
                  <div class="tree-list">
                    {#each folderTree as rootNode}
                      <FolderTreeNode 
                        node={rootNode} 
                        {excludedFolders} 
                        {expandedNodes} 
                        {hideUnselected}
                        on:toggleCheck={handleTreeCheckToggle}
                        on:toggleExpand={handleTreeExpandToggle}
                      />
                    {/each}
                  </div>
                </section>

                <!-- Conflict Resolution Panel -->
                <section class="card glass scrollable">
                  <h2>Duplicate Module Definitions</h2>
                  <p class="subtitle">We found the same module defined in multiple files. Choose which definition to keep active to prevent build conflicts.</p>

                  {#if preScanData.duplicates.length === 0}
                    <div class="empty-state">No duplicate module definition conflicts found.</div>
                  {:else}
                    <div class="duplicate-list">
                      {#each preScanData.duplicates as dup}
                        <div class="duplicate-card">
                          <h3>Module: <code>{dup.module}</code></h3>
                          <div class="radio-group">
                            {#each dup.paths as p}
                              <label class="radio-label">
                                <input 
                                  type="radio" 
                                  name={dup.module} 
                                  value={p} 
                                  bind:group={resolvedDuplicates[dup.module]} 
                                />
                                <span class="file-path-radio">{p}</span>
                              </label>
                            {/each}
                          </div>
                        </div>
                      {/each}
                    </div>
                  {/if}

                  <div class="action-footer">
                    <input 
                      type="file" 
                      accept=".json" 
                      style="display: none" 
                      bind:this={fileInput} 
                      on:change={handleFileLoad} 
                    />
                    <button class="btn btn-secondary" on:click={() => step = 'setup'}>Back</button>
                    <button class="btn btn-secondary" on:click={triggerFilePicker}>Load Config File</button>
                    <button class="btn btn-secondary" on:click={handleRestoreConfig}>Restore Saved</button>
                    <button class="btn btn-info" on:click={handleSaveConfigOnly}>Save Config</button>
                    <button class="btn btn-primary" on:click={handleStartRun} disabled={runStatus.running && runStatus.validation_status !== 'paused'}>Launch Pipeline</button>
                    {#if saveConfigStatus}
                      <span class="status-msg">{saveConfigStatus}</span>
                    {/if}
                  </div>
                </section>
              </div>
            {/if}

            <!-- RUNNING / RESULTS MONITOR STEP -->
            {#if step === 'running' || step === 'results'}
              <div class="results-grid">
                <!-- Left Side: Stats and Module List -->
                <div class="left-panel">
                  <section class="card glass stats-card">
                    <div class="stats-header">
                      <h2>Validation Status</h2>
                      {#if step === 'results'}
                        <div style="display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap;">
                          <button class="btn btn-secondary btn-sm" on:click={() => step = 'config'}>Configure</button>
                          <button class="btn btn-secondary btn-sm" on:click={handleReRun} disabled={runStatus.running && runStatus.validation_status !== 'paused'}>Clean & Re-run</button>
                          {#if runStatus.failed > 0}
                            <button class="btn btn-warning btn-sm" on:click={handleRepair} disabled={isRepairing || (runStatus.running && runStatus.validation_status !== 'paused')}>
                              {isRepairing ? 'Repairing...' : 'Launch Failure Repair'}
                            </button>
                          {/if}
                          <button class="btn btn-success btn-sm" on:click={handleProceed} disabled={isProceeding || (runStatus.running && runStatus.validation_status !== 'paused')}>
                            {isProceeding ? 'Proceeding...' : 'Proceed to Workers'}
                          </button>
                          {#if proceedStatus}
                            <span style="font-size: 0.85rem; color: var(--success-green); margin-left: 0.5rem;">{proceedStatus}</span>
                          {/if}
                        </div>
                      {/if}
                      {#if step === 'running' || (runStatus.running && runStatus.validation_status !== 'idle')}
                        <div class="process-controls" style="display: flex; gap: 0.5rem; align-items: center; margin-left: auto;">
                          {#if runStatus.validation_status === 'paused'}
                            <button class="btn btn-success btn-sm" on:click={resumePipeline}>Resume</button>
                          {:else}
                            <button class="btn btn-warning btn-sm" on:click={pausePipeline}>Pause</button>
                          {/if}
                          <button class="btn btn-danger btn-sm" on:click={abortPipeline}>Abort</button>
                        </div>
                      {/if}
                    </div>
                    
                    <div class="progress-bar-container">
                      <div class="progress-info">
                        <span>Verification Progress</span>
                        <span>{runStatus.completed_modules} / {runStatus.total_modules} Modules</span>
                      </div>
                      <div class="progress-track">
                        <div class="progress-fill" style="width: {runStatus.progress}%"></div>
                      </div>
                    </div>

                    <div class="stats-counters">
                      <div class="stat-box success">
                        <span class="number">{runStatus.fully_validated}</span>
                        <span class="label">Fully Validated</span>
                      </div>
                      <div class="stat-box partial">
                        <span class="number">{runStatus.partially_validated}</span>
                        <span class="label">Missing Stub</span>
                      </div>
                      <div class="stat-box danger">
                        <span class="number">{runStatus.failed}</span>
                        <span class="label">Failed</span>
                      </div>
                    </div>
                  </section>

                  <!-- Module List Grid -->
                  <section class="card glass modules-list-card scrollable">
                    <div class="list-header">
                      <h2>Module Auditing Inventory</h2>
                      <div class="filters">
                        <input type="text" placeholder="Search module name..." bind:value={filterText} class="search-input" />
                        <select bind:value={statusFilter} class="status-select">
                          <option value="ALL">All Statuses</option>
                          <option value="VALIDATED">Fully Validated</option>
                          <option value="PARTIAL">Missing Stub</option>
                          <option value="FAILED">Failed</option>
                          <option value="UNVALIDATED">Queued</option>
                        </select>
                      </div>
                    </div>
                    <div class="table-container">
                      <table class="modules-table">
                        <thead>
                          <tr>
                            <th>Module Name</th>
                            <th>Status</th>
                            <th>Defining Source File</th>
                          </tr>
                        </thead>
                        <tbody>
                          {#each filteredModules as mod}
                            <tr>
                              <td><strong>{mod.name}</strong></td>
                              <td>
                                {#if mod.status === 'FAILED' || mod.status === 'PARTIAL'}
                                  <span 
                                    class="badge status-{mod.status.toLowerCase()} clickable-badge" 
                                    title="Click to view error diagnostics and stub details"
                                    role="button"
                                    tabindex="0"
                                    on:click={() => selectedModuleForDetail = mod}
                                    on:keydown={(e) => (e.key === 'Enter' || e.key === ' ') && (selectedModuleForDetail = mod)}
                                  >
                                    {mod.status === 'PARTIAL' ? 'MISSING STUB' : mod.status}
                                  </span>
                                {:else}
                                  <span class="badge status-{mod.status.toLowerCase()}">
                                    {mod.status}
                                  </span>
                                {/if}
                              </td>
                              <td class="file-cell" title={mod.defined_in}>{mod.defined_in}</td>
                            </tr>
                          {/each}
                        </tbody>
                      </table>
                    </div>
                  </section>
                </div>

                <!-- Right Side: Live Logs -->
                <section class="card glass console-card">
                  <div class="console-header-row">
                    <h2 style="margin: 0;">Console Execution Stream</h2>
                    <div class="console-tabs">
                      <button 
                        class="console-tab-btn {selectedConsoleLogTab === 'validation' ? 'active' : ''}" 
                        on:click={() => selectedConsoleLogTab = 'validation'}
                      >
                        Validation Stream
                      </button>
                      <button 
                        class="console-tab-btn {selectedConsoleLogTab === 'repair' ? 'active' : ''}" 
                        on:click={() => selectedConsoleLogTab = 'repair'}
                      >
                        AI Repair Stream
                      </button>
                    </div>
                  </div>
                  <div class="console-box" id="console" bind:this={consoleElement}>
                    {#each logsToDisplay as log}
                      <div class="console-line">{log}</div>
                    {/each}
                    {#if logsToDisplay.length === 0}
                      <div class="console-line empty-log">No logs recorded for this stream.</div>
                    {/if}
                  </div>
                  {#if runStatus.running && selectedConsoleLogTab === runStatus.current_stream_type}
                    <div class="console-input-area">
                      <input 
                        type="text" 
                        placeholder="Type response (e.g. y/n) and press Enter..." 
                        bind:value={consoleInputText} 
                        on:keydown={(e) => e.key === 'Enter' && handleConsoleInputSubmit()} 
                        class="console-input-field"
                      />
                      <button class="btn btn-primary btn-sm" on:click={handleConsoleInputSubmit}>Send</button>
                    </div>
                  {/if}
                </section>
              </div>
            {/if}

          {:else if activePhase === 'phase-0.3'}
            <!-- Context Viewer Panel -->
            <section class="card glass context-panel">
              <div class="panel-header-row">
                <div>
                  <h2>SoC Design Context (Phase 0.3)</h2>
                  <p class="subtitle">Discovered design topology, trust boundaries, and keywords mapped from SystemVerilog source code analysis.</p>
                </div>
                <div class="tab-buttons">
                  <button class="tab-btn {contextSubTab === 'hierarchy' ? 'active' : ''}" on:click={() => contextSubTab = 'hierarchy'}>Hierarchy Tree</button>
                  <button class="tab-btn {contextSubTab === 'secrets' ? 'active' : ''}" on:click={() => contextSubTab = 'secrets'}>Secret Signals</button>
                  <button class="tab-btn {contextSubTab === 'trust' ? 'active' : ''}" on:click={() => contextSubTab = 'trust'}>Trust Boundaries</button>
                </div>
              </div>

              {#if !contextData || !contextData.module_hierarchy}
                <div class="empty-state">
                  <div class="pulse-dot"></div>
                  <p>Design Context data is not yet available. Run the validation pipeline to generate AST contexts.</p>
                </div>
              {:else}
                <div class="context-content-grid">
                  <!-- Left side: Sub-tab specific content -->
                  <div class="context-main-view scrollable">
                    {#if contextSubTab === 'hierarchy'}
                      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                        <h3>Instantiation Tree</h3>
                        <button class="btn btn-secondary btn-sm" on:click={fetchContext}>Refresh Data</button>
                      </div>
                      <div class="tree-nodes-list">
                        {#each flatHierarchy as node}
                          <div 
                            class="tree-node-item {selectedContextModule === node.name ? 'selected' : ''}" 
                            style="padding-left: {node.level * 16 + 8}px"
                            role="button"
                            tabindex="0"
                            on:click={() => selectedContextModule = node.name}
                            on:keydown={(e) => (e.key === 'Enter' || e.key === ' ') && (selectedContextModule = node.name)}
                          >
                            <span class="tree-connector">├─</span>
                            <span class="node-icon">📦</span>
                            <strong>{node.name}</strong> 
                            {#if node.instName}
                              <span class="inst-name">({node.instName})</span>
                            {/if}
                          </div>
                        {/each}
                      </div>

                    {:else if contextSubTab === 'secrets'}
                      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                        <h3>Sensitive Signals & Registers</h3>
                        <button class="btn btn-secondary btn-sm" on:click={fetchContext}>Refresh Data</button>
                      </div>
                      {#if !contextData.secret_signals || Object.keys(contextData.secret_signals).length === 0}
                        <div class="empty-state">No secret signals tagged in this design.</div>
                      {:else}
                        <div class="table-container">
                          <table class="modules-table">
                            <thead>
                              <tr>
                                <th>Module</th>
                                <th>Signal/Port Name</th>
                                <th>Direction</th>
                                <th>Type</th>
                                <th>Reasoning</th>
                              </tr>
                            </thead>
                            <tbody>
                              {#each Object.entries(contextData.secret_signals) as [mod, signals]}
                                {#if Array.isArray(signals)}
                                  {#each signals as sig}
                                    <tr class="clickable-row" role="button" tabindex="0" on:click={() => selectedContextModule = mod} on:keydown={(e) => (e.key === 'Enter' || e.key === ' ') && (selectedContextModule = mod)}>
                                      <td><strong>{mod}</strong></td>
                                      <td><code class="secret-code">{sig.name || sig}</code></td>
                                      <td>{sig.direction || 'internal'}</td>
                                      <td>{sig.type || 'logic'}</td>
                                      <td><span class="reason-tag">{sig.reason || 'Keyword matched'}</span></td>
                                    </tr>
                                  {/each}
                                {/if}
                              {/each}
                            </tbody>
                          </table>
                        </div>
                      {/if}

                    {:else if contextSubTab === 'trust'}
                      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                        <h3>Trust Boundaries & Clocks</h3>
                        <button class="btn btn-secondary btn-sm" on:click={fetchContext}>Refresh Data</button>
                      </div>
                      {#if !contextData.trust_boundaries || Object.keys(contextData.trust_boundaries).length === 0}
                        <div class="empty-state">No trust boundary mappings found.</div>
                      {:else}
                        <div class="table-container">
                          <table class="modules-table">
                            <thead>
                              <tr>
                                <th>Module Name</th>
                                <th>Security Trust Boundary</th>
                                <th>Clock/Reset Pins</th>
                              </tr>
                            </thead>
                            <tbody>
                              {#each Object.entries(contextData.trust_boundaries) as [mod, boundary]}
                                <tr class="clickable-row" role="button" tabindex="0" on:click={() => selectedContextModule = mod} on:keydown={(e) => (e.key === 'Enter' || e.key === ' ') && (selectedContextModule = mod)}>
                                  <td><strong>{mod}</strong></td>
                                  <td>
                                    <span class="badge trust-{String(boundary).toLowerCase().replace('_', '-')}">
                                      {boundary}
                                    </span>
                                  </td>
                                  <td>
                                    {#if contextData.clock_domains && contextData.clock_domains[mod]}
                                      <code>{contextData.clock_domains[mod].clock || 'clk'}</code> / <code>{contextData.clock_domains[mod].reset || 'rst_n'}</code>
                                    {:else}
                                      <span class="text-muted">Default (clk / rst_n)</span>
                                    {/if}
                                  </td>
                                </tr>
                              {/each}
                            </tbody>
                          </table>
                        </div>
                      {/if}
                    {/if}
                  </div>

                  <!-- Right side: Selected Module Profile card -->
                  <div class="context-detail-panel card glass">
                    {#if selectedContextModule}
                      <div class="detail-header-row">
                        <h3>Module Profile: <code>{selectedContextModule}</code></h3>
                        <button class="close-btn" on:click={() => selectedContextModule = ''}>&times;</button>
                      </div>
                      
                      <div class="profile-field">
                        <span class="profile-label">Trust Boundary Classification:</span>
                        <span class="badge trust-{String(contextData.trust_boundaries?.[selectedContextModule] || 'INTERNAL_LOGIC').toLowerCase().replace('_', '-')}">
                          {contextData.trust_boundaries?.[selectedContextModule] || 'INTERNAL_LOGIC'}
                        </span>
                      </div>

                      <div class="profile-field">
                        <span class="profile-label">Clock Domain:</span>
                        <code>{contextData.clock_domains?.[selectedContextModule]?.clock || 'clk'}</code> (Reset: <code>{contextData.clock_domains?.[selectedContextModule]?.reset || 'rst_n'}</code>)
                      </div>

                      <div class="profile-field">
                        <span class="profile-label">Security Summary & Context:</span>
                        <div class="summary-box">
                          {contextData.module_summaries?.[selectedContextModule] || 'No summary text generated for this module.'}
                        </div>
                      </div>

                      <div class="profile-field">
                        <span class="profile-label">Tagged Secrets ({contextData.secret_signals?.[selectedContextModule]?.length || 0}):</span>
                        {#if contextData.secret_signals?.[selectedContextModule] && contextData.secret_signals[selectedContextModule].length > 0}
                          <ul class="secrets-bullet-list">
                            {#each contextData.secret_signals[selectedContextModule] as sig}
                              <li>
                                <code class="secret-code">{sig.name || sig}</code> 
                                <span class="sig-meta">({sig.direction || 'internal'} {sig.type || 'logic'}) - {sig.reason || 'Keyword match'}</span>
                              </li>
                            {/each}
                          </ul>
                        {:else}
                          <p class="empty-text">No secret signal tags inside this module.</p>
                        {/if}
                      </div>
                    {:else}
                      <div class="empty-detail-state">
                        <span class="icon">📋</span>
                        <p>Select a module from the hierarchy tree or tables to inspect its deep security profile and compressed text summaries.</p>
                      </div>
                    {/if}
                  </div>
                </div>
              {/if}
            </section>

          {:else if activePhase === 'phase-0.4'}
            <!-- Synthesis Orchestrator Panel -->
            <section class="card glass synthesis-panel">
              <div class="panel-header-row" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 1rem;">
                <div>
                  <h2 style="margin: 0;">Shared Synthesis Orchestrator (Phase 0.4)</h2>
                  <p class="subtitle" style="margin: 0.2rem 0 0 0; color: var(--text-secondary); font-size: 0.9rem;">Triggers module-wise netlist slice generation using Yosys and executes AI static analysis on synthesis warnings.</p>
                </div>
                <div>
                  {#if synthesisStatus.synthesis_running}
                    <div style="display: flex; gap: 0.5rem; align-items: center;">
                      {#if synthesisStatus.synthesis_status === 'paused'}
                        <button class="btn btn-success" on:click={resumeSynthesis}>
                          Resume
                        </button>
                      {:else}
                        <button class="btn btn-warning" on:click={pauseSynthesis} style="background: var(--warning-amber); border-color: var(--warning-amber); color: #fff;">
                          Pause
                        </button>
                      {/if}
                      <button class="btn btn-danger" on:click={abortSynthesis}>
                        Abort
                      </button>
                    </div>
                  {:else}
                    <button class="btn btn-primary" on:click={startSynthesis} disabled={synthesisStatus.synthesis_running && synthesisStatus.synthesis_status !== 'paused'}>
                      Run Yosys Synthesis
                    </button>
                  {/if}
                </div>
              </div>

              {#if !synthesisStatus.synthesis_running && synthesisStatus.synthesis_status === 'idle' && (!synthesisStatus.modules || synthesisStatus.modules.length === 0)}
                <div class="config-panel" style="padding: 1.5rem; background: rgba(255,255,255,0.02); border-radius: 8px; border: 1px solid rgba(255,255,255,0.1); margin-bottom: 1.5rem;">
                  <h3 style="margin-top: 0;">Synthesis Configuration</h3>
                  
                  <div style="margin-bottom: 1rem;">
                    <div class="form-group">
                      <label>Top Module Name</label>
                      <input type="text" bind:value={synthConfig.top_module} placeholder="e.g. chip_earlgrey_asic" />
                    </div>
                  </div>

                  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 0.5rem;">
                    <div class="form-group">
                      <label>FuseSoC Cores Root (optional)</label>
                      <input type="text" bind:value={synthConfig.fusesoc_cores_root} placeholder="e.g. hw/" />
                    </div>
                    <div class="form-group">
                      <label>FuseSoC Core Name (optional)</label>
                      <div style="display: flex; gap: 0.5rem;">
                        <input type="text" bind:value={synthConfig.fusesoc_core_name} placeholder="e.g. lowrisc:systems:chip_earlgrey_asic" style="flex: 1;" />
                        <button class="btn btn-secondary btn-sm" on:click={autodetectFusesoc} style="white-space: nowrap;">Auto-detect</button>
                      </div>
                    </div>
                  </div>
                  {#if autodetectStatus}
                    <div style="color: var(--accent-color); font-size: 0.85rem; margin-bottom: 1rem; text-align: right;">{autodetectStatus}</div>
                  {/if}

                  <div style="display: flex; gap: 2rem; align-items: center; margin-top: 1rem;">
                    <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                      <input type="checkbox" bind:checked={synthConfig.run_slang_elab_check} />
                      Run Slang Elaboration Check
                    </label>
                    <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                      <input type="checkbox" bind:checked={synthConfig.auto_generate_stubs} />
                      Auto-Generate Stubs on Error
                    </label>
                    <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                      <input type="checkbox" bind:checked={synthConfig.escalate_to_ai_on_failure} />
                      Escalate to AI on Failure
                    </label>
                  </div>
                </div>
              {:else}
                <div class="context-content-grid" style="display: grid; grid-template-columns: 1fr 1.2fr; gap: 1.5rem; min-height: 350px; margin-bottom: 1.5rem;">
                  <!-- Left side: Module list with status -->
                  <div class="context-main-view scrollable" style="overflow-y: auto; padding-right: 0.5rem; border-right: 1px solid rgba(255,255,255,0.06); max-height: 55vh;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 0;">
                      <h3 style="margin: 0;">Approved Modules Status</h3>
                      <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer; font-size: 0.85rem; color: var(--text-secondary);">
                        <input type="checkbox" bind:checked={showInternalModules} />
                        Show Internal Modules
                      </label>
                    </div>
                    <div class="table-container" style="margin-top: 1rem;">
                      <table class="modules-table" style="width: 100%; border-collapse: collapse;">
                        <thead>
                          <tr style="text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1);">
                            <th style="padding: 0.5rem;">Module Name</th>
                            <th style="padding: 0.5rem;">Status</th>
                            <th style="padding: 0.5rem;">Warnings</th>
                            <th style="padding: 0.5rem;">Errors</th>
                            <th style="padding: 0.5rem;">AI Risk</th>
                          </tr>
                        </thead>
                        <tbody>
                          {#each synthesisStatus.modules.filter(m => showInternalModules || !m.name.includes('$')) as mod}
                            <tr 
                              class="clickable-row {selectedSynthesisModule === mod.name ? 'selected-row' : ''}" 
                              role="button" 
                              tabindex="0" 
                              on:click={() => fetchSynthesisModuleDetail(mod.name)} 
                              on:keydown={(e) => (e.key === 'Enter' || e.key === ' ') && fetchSynthesisModuleDetail(mod.name)}
                              style="cursor: pointer; border-bottom: 1px solid rgba(255,255,255,0.04); transition: background 0.2s;"
                            >
                              <td style="padding: 0.6rem 0.5rem;"><strong>{mod.name}</strong></td>
                              <td style="padding: 0.6rem 0.5rem;">
                                <span class="badge status-{mod.status.toLowerCase()}">
                                  {mod.status}
                                </span>
                              </td>
                              <td style="padding: 0.6rem 0.5rem;">{mod.warning_count}</td>
                              <td style="padding: 0.6rem 0.5rem;">{mod.error_count}</td>
                              <td style="padding: 0.6rem 0.5rem;">
                                <span class="badge risk-{mod.risk_level.toLowerCase()}">
                                  {mod.risk_level}
                                </span>
                              </td>
                            </tr>
                          {/each}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  <!-- Right side: Synthesis Log and AI security findings detail panel -->
                  <div class="context-detail-panel card glass scrollable" style="overflow-y: auto; padding: 1rem; background: rgba(0,0,0,0.15); border-radius: 8px; max-height: 55vh;">
                    {#if selectedSynthesisModule && selectedSynthesisDetail}
                      <div class="detail-header-row" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 0.5rem;">
                        <h3 style="margin: 0;">Synthesis Report: <code>{selectedSynthesisModule}</code></h3>
                        <button class="close-btn" on:click={() => { selectedSynthesisModule = ''; selectedSynthesisDetail = null; }} style="background: none; border: none; color: var(--text-secondary); font-size: 1.5rem; cursor: pointer;">&times;</button>
                      </div>

                      <!-- Netlist Metadata -->
                      {#if selectedSynthesisDetail.netlist_metadata && selectedSynthesisDetail.netlist_metadata.cell_count !== undefined}
                        <div class="profile-field" style="margin-bottom: 1.5rem;">
                          <span class="profile-label" style="display: block; font-weight: bold; margin-bottom: 0.5rem; color: var(--accent-color);">Synthesized Netlist Statistics:</span>
                          <div class="stats-grid">
                            <div class="stat-card">
                              <span class="stat-num">{selectedSynthesisDetail.netlist_metadata.port_count}</span>
                              <span class="stat-label">Ports</span>
                            </div>
                            <div class="stat-card">
                              <span class="stat-num">{selectedSynthesisDetail.netlist_metadata.cell_count}</span>
                              <span class="stat-label">Total Cells</span>
                            </div>
                          </div>
                          {#if Object.keys(selectedSynthesisDetail.netlist_metadata.cells_summary).length > 0}
                            <h5 style="margin: 0.8rem 0 0.4rem 0;">Cell Library Allocation</h5>
                            <ul class="secrets-bullet-list" style="margin: 0; padding-left: 1.2rem; font-size: 0.9rem;">
                              {#each Object.entries(selectedSynthesisDetail.netlist_metadata.cells_summary) as [cellType, count]}
                                <li style="margin-bottom: 0.2rem;"><code>{cellType}</code>: {count} instances</li>
                              {/each}
                            </ul>
                          {/if}
                        </div>
                      {/if}

                      <!-- AI Security Findings -->
                      <div class="profile-field" style="margin-bottom: 1.5rem;">
                        <span class="profile-label" style="display: block; font-weight: bold; margin-bottom: 0.5rem; color: var(--accent-color);">AI Static Security Review:</span>
                        {#if selectedSynthesisDetail.ai_interpretation}
                          <div class="risk-summary" style="margin-top: 0.5rem; padding: 0.5rem; border-radius: 4px; background: rgba(255,255,255,0.03); border-left: 4px solid var(--warning-amber);">
                            <strong>Overall Risk Boundary Level: </strong>
                            <span class="badge risk-{selectedSynthesisDetail.ai_interpretation.risk_level?.toLowerCase()}">{selectedSynthesisDetail.ai_interpretation.risk_level || 'LOW'}</span>
                          </div>
                          
                          {#if selectedSynthesisDetail.ai_interpretation.security_warnings && selectedSynthesisDetail.ai_interpretation.security_warnings.length > 0}
                            <div class="findings-list" style="margin-top: 1rem;">
                              {#each selectedSynthesisDetail.ai_interpretation.security_warnings as warning}
                                <div class="finding-card card glass" style="padding: 0.8rem; margin-bottom: 0.8rem; background: rgba(0,0,0,0.2); border: 1px solid rgba(255,255,255,0.05); border-radius: 6px;">
                                  <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
                                    <strong style="color: #f0f3f6;">⚠️ {warning.finding}</strong>
                                    <span class="badge risk-{warning.severity?.toLowerCase()}">{warning.severity}</span>
                                  </div>
                                  <p style="margin: 0 0 0.4rem 0; font-size: 0.9rem; color: #8b949e;">{warning.explanation}</p>
                                  <p style="margin: 0; font-size: 0.9rem; color: var(--accent-color, #58a6ff);">💡 <strong>Recommendation:</strong> {warning.recommendation}</p>
                                </div>
                              {/each}
                            </div>
                          {:else}
                            <p class="empty-text" style="color: var(--text-secondary); font-style: italic;">No security findings flagged by static log review.</p>
                          {/if}
                        {:else}
                          <p class="empty-text" style="color: var(--text-secondary); font-style: italic;">No AI security assessment available yet.</p>
                        {/if}
                      </div>
                      <!-- Worker Payload Preview -->
                      {#if selectedSynthesisDetail.worker_payload_preview}
                        <div class="profile-field" style="margin-bottom: 1.5rem;">
                          <span class="profile-label" style="display: block; font-weight: bold; margin-bottom: 0.5rem; color: var(--accent-color);">Worker AI Payload Preview:</span>
                          <div class="console-box" style="font-family: monospace; font-size: 0.85rem; max-height: 250px; overflow-y: auto; background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 6px; color: #e5e7eb; border: 1px solid rgba(255,255,255,0.08);">
                            <pre style="margin: 0; white-space: pre-wrap;"><code>{JSON.stringify(selectedSynthesisDetail.worker_payload_preview, null, 2)}</code></pre>
                          </div>
                        </div>
                      {/if}

                      <!-- Compiler logs -->
                      <div class="profile-field" style="margin-bottom: 1.5rem;">
                        <span class="profile-label" style="display: block; font-weight: bold; margin-bottom: 0.5rem; color: var(--accent-color);">Yosys Compiler Stdout/Stderr:</span>
                        <div class="console-box" style="font-family: monospace; font-size: 0.8rem; max-height: 250px; overflow-y: auto; background: #07090e; padding: 0.5rem; border-radius: 4px; color: #a5b4fc;">
                          {#each (selectedSynthesisDetail.log || '').split('\n') as line}
                            <div class="console-line" style="margin-bottom: 0.1rem; line-height: 1.3;">{line}</div>
                          {/each}
                          {#if !selectedSynthesisDetail.log}
                            <div class="console-line empty-log" style="color: var(--text-secondary); font-style: italic;">No compilation output recorded.</div>
                          {/if}
                        </div>
                      </div>

                    {:else}
                      <div class="empty-detail-state" style="text-align: center; padding: 4rem 1rem; color: var(--text-secondary);">
                        <span class="icon" style="font-size: 2.5rem; display: block; margin-bottom: 1rem;">📋</span>
                        <p>Select a synthesized module from the list to inspect its netlist cell stats, AI compiler warnings review, and raw execution logs.</p>
                      </div>
                    {/if}
                  </div>
                </div>
              {/if}

                <!-- Sub-tabbed Console Streams for Synthesis -->
                <div class="synthesis-console-section" style="border-top: 1px solid rgba(255,255,255,0.06); padding-top: 1rem; display: flex; flex-direction: column; gap: 0.5rem;">
                  <div class="console-header-row" style="display: flex; justify-content: space-between; align-items: center;">
                    <h3 style="margin: 0; font-size: 1rem; color: #f0f3f6;">
                      Synthesis Console Streams
                      {#if synthesisStatus.synthesis_running && synthesisStatus.synthesis_status === 'paused'}
                        <span class="badge status-paused" style="margin-left: 0.5rem; font-size: 0.75rem;">PAUSED</span>
                      {:else if synthesisStatus.synthesis_running}
                        <span class="badge status-running" style="margin-left: 0.5rem; font-size: 0.75rem;">RUNNING</span>
                      {:else if synthesisStatus.synthesis_status === 'completed'}
                        <span class="badge status-completed" style="margin-left: 0.5rem; font-size: 0.75rem;">COMPLETED</span>
                      {:else if synthesisStatus.synthesis_status === 'failed'}
                        <span class="badge status-failed" style="margin-left: 0.5rem; font-size: 0.75rem;">FAILED</span>
                      {:else}
                        <span class="badge status-idle" style="margin-left: 0.5rem; font-size: 0.75rem;">IDLE</span>
                      {/if}
                    </h3>
                    <div class="console-tabs" style="display: flex; gap: 0.25rem; overflow-x: auto; max-width: 70%; padding-bottom: 0.2rem;">
                      <button 
                        class="console-tab-btn {selectedSynthesisConsoleTab === 'general' ? 'active' : ''}" 
                        on:click={() => selectedSynthesisConsoleTab = 'general'}
                        style="padding: 0.25rem 0.6rem; font-size: 0.8rem; border-radius: 4px;"
                      >
                        General Synthesis Log
                      </button>
                      {#each synthesisStatus.modules as mod}
                        {#if mod.status !== 'UNVALIDATED'}
                          <button 
                            class="console-tab-btn {selectedSynthesisConsoleTab === mod.name ? 'active' : ''}" 
                            on:click={() => selectSynthesisModuleConsole(mod.name)}
                            style="padding: 0.25rem 0.6rem; font-size: 0.8rem; border-radius: 4px;"
                          >
                            {mod.name}
                          </button>
                        {/if}
                      {/each}
                    </div>
                  </div>
                  <div class="console-box" style="font-family: monospace; font-size: 0.85rem; height: 200px; overflow-y: auto; background: #07090e; padding: 0.5rem; border-radius: 6px; color: #a5b4fc; border: 1px solid rgba(255,255,255,0.08);">
                    {#if selectedSynthesisConsoleTab === 'general'}
                      {#each (synthesisStatus.synthesis_logs || []) as line}
                        <div class="console-line" style="margin-bottom: 0.1rem; line-height: 1.3;">{line}</div>
                      {/each}
                      {#if !(synthesisStatus.synthesis_logs && synthesisStatus.synthesis_logs.length)}
                        <div class="console-line empty-log" style="color: var(--text-secondary); font-style: italic;">No synthesis logs recorded.</div>
                      {/if}
                    {:else}
                      {#if activeModuleLogLoading}
                        <div class="console-line" style="margin-bottom: 0.1rem; line-height: 1.3;"><span class="spinner">⏳</span> Loading log for {selectedSynthesisConsoleTab}...</div>
                      {:else}
                        {#each (activeModuleLogText || '').split('\n') as line}
                          <div class="console-line" style="margin-bottom: 0.1rem; line-height: 1.3;">{line}</div>
                        {/each}
                        {#if !activeModuleLogText}
                          <div class="console-line empty-log" style="color: var(--text-secondary); font-style: italic;">No compilation output recorded for {selectedSynthesisConsoleTab}.</div>
                        {/if}
                      {/if}
                    {/if}
                  </div>
            </section>

          {:else}
            <!-- LOCKED PHASES PLACEHOLDER -->
            <section class="card glass locked-panel">
              <div class="locked-card-content">
                <span class="locked-icon">🔒</span>
                <h2>{activePhase === 'phase-1' ? 'Phase 1: Worker Static Auditing' : activePhase === 'phase-2' ? 'Phase 2: Waveform Security Analysis' : 'Phase 3: Formal Security Proofs'}</h2>
                <p class="subtitle">This phase is currently locked. Complete Phase 0 (Environment Validation, Repair, and Design Context Generation) and click "Proceed to Workers" to forward approved modules to worker agents.</p>
                <button class="btn btn-secondary btn-sm" on:click={() => activePhase = 'phase-0.1-0.2'}>← Go Back to Validation</button>
              </div>
            </section>
          {/if}
        </div>
      </div>
    {/if}
  </div>

  {#if showLaunchModal}
    <div class="modal-backdrop">
      <div class="modal card glass">
        <h2>Existing Run Detected</h2>
        <p>A previous validation run with {runStatus.completed_modules} completed modules exists on disk for project "{projectName}".</p>
        <p style="color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 1.5rem;">
          Running a clean validation will wipe the previous results to start fresh. Loading will view the existing results dashboard directly.
        </p>
        <div class="modal-actions">
          <button class="btn btn-secondary" on:click={() => { showLaunchModal = false; step = 'results'; }}>Load Previous Results</button>
          <button class="btn btn-primary" on:click={confirmCleanRun}>Run Clean Validation</button>
        </div>
      </div>
    </div>
  {/if}

  {#if selectedModuleForDetail}
    <div class="modal-backdrop" role="button" tabindex="0" on:click={() => selectedModuleForDetail = null} on:keydown={(e) => (e.key === 'Escape' || e.key === 'Enter') && (selectedModuleForDetail = null)}>
      <div class="modal card glass detail-modal" role="dialog" aria-modal="true" on:click|stopPropagation on:keydown|stopPropagation>
        <div class="detail-header">
          <h2>Module Diagnostic Report: <code>{selectedModuleForDetail.name}</code></h2>
          <button class="close-btn" on:click={() => selectedModuleForDetail = null}>&times;</button>
        </div>
        
        <div class="detail-body">
          <div class="detail-row">
            <span class="detail-label">Status:</span>
            <span class="badge status-{selectedModuleForDetail.status.toLowerCase()}">
              {selectedModuleForDetail.status === 'PARTIAL' ? 'MISSING STUB' : selectedModuleForDetail.status}
            </span>
          </div>
          
          <div class="detail-row">
            <span class="detail-label">Source File:</span>
            <span class="detail-value-path">{selectedModuleForDetail.defined_in}</span>
          </div>

          <div class="detail-section">
            <h3>Stubs Created & Compiled</h3>
            {#if selectedModuleForDetail.stubs && selectedModuleForDetail.stubs.length > 0}
              <ul class="stubs-list">
                {#each selectedModuleForDetail.stubs as stub}
                  <li><code>{stub}</code></li>
                {/each}
              </ul>
            {:else}
              <p class="empty-text">No stub files were generated or required for this module.</p>
            {/if}
          </div>

          {#if selectedModuleForDetail.errors && Object.keys(selectedModuleForDetail.errors).length > 0}
            <div class="detail-section">
              <h3>Compiler Error Diagnostics</h3>
              {#each Object.entries(selectedModuleForDetail.errors) as [tool, errText]}
                <div class="tool-error-box">
                  <div class="tool-error-header">{tool} Output</div>
                  <pre class="tool-error-pre">{errText}</pre>
                </div>
              {/each}
            </div>
          {/if}
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
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-dark);
    color: var(--text-primary);
    overflow-x: hidden;
  }

  .dashboard-root {
    display: flex;
    flex-direction: column;
    height: 100vh;
    box-sizing: border-box;
  }

  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem 2rem;
    border-bottom: 1px solid var(--border-color);
    background: rgba(10, 14, 23, 0.8);
    backdrop-filter: blur(12px);
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .logo h1 {
    font-size: 1.25rem;
    margin: 0;
    font-weight: 700;
    letter-spacing: 0.5px;
    background: linear-gradient(90deg, #fff, var(--text-secondary));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  .pulse-dot {
    width: 8px;
    height: 8px;
    background-color: var(--success-green);
    border-radius: 50%;
    box-shadow: 0 0 12px var(--success-green);
    animation: pulse 2s infinite;
  }

  @keyframes pulse {
    0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 230, 118, 0.7); }
    70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(0, 230, 118, 0); }
    100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 230, 118, 0); }
  }

  .content-container {
    flex: 1;
    padding: 2rem;
    overflow-y: auto;
  }

  .card {
    background: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 2rem;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.37);
  }

  .glass {
    backdrop-filter: blur(8px);
  }

  .scrollable {
    overflow-y: auto;
    max-height: 70vh;
  }

  h2 {
    margin-top: 0;
    font-size: 1.5rem;
    font-weight: 600;
  }

  .subtitle {
    color: var(--text-secondary);
    margin-top: -0.5rem;
    margin-bottom: 1.5rem;
    font-size: 0.9rem;
  }

  .form-group {
    margin-bottom: 1.25rem;
  }

  label {
    display: block;
    margin-bottom: 0.5rem;
    font-size: 0.85rem;
    color: var(--text-secondary);
  }

  input[type="text"] {
    width: 100%;
    padding: 0.75rem;
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    color: #fff;
    font-size: 0.95rem;
    box-sizing: border-box;
    transition: border-color 0.25s;
  }

  input[type="text"]:focus {
    outline: none;
    border-color: var(--accent-blue);
  }

  .btn {
    padding: 0.75rem 1.5rem;
    border-radius: 6px;
    font-weight: 600;
    cursor: pointer;
    border: none;
    transition: background 0.2s, transform 0.1s;
  }

  .btn-primary {
    background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
    color: #fff;
  }

  .btn-primary:hover {
    opacity: 0.9;
  }

  .btn-secondary {
    background: rgba(255, 255, 255, 0.08);
    color: var(--text-primary);
  }

  .btn-secondary:hover {
    background: rgba(255, 255, 255, 0.15);
  }

  .btn-info {
    background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
    color: #fff;
    opacity: 0.85;
  }

  .btn-info:hover {
    opacity: 1.0;
  }

  .status-msg {
    margin-left: 1rem;
    align-self: center;
    font-size: 0.9rem;
    color: #10b981;
    font-weight: 500;
  }

  .alert {
    padding: 0.75rem;
    border-radius: 6px;
    margin-bottom: 1.25rem;
    font-size: 0.9rem;
  }

  .alert.error {
    background: rgba(255, 61, 0, 0.15);
    border: 1px solid var(--danger-red);
    color: #ff8a80;
  }

  .panel-header-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
  }

  .config-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2rem;
  }

  .tree-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .tree-item {
    padding: 0.5rem;
    border-radius: 6px;
    background: rgba(255, 255, 255, 0.01);
    border: 1px solid transparent;
  }

  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    cursor: pointer;
  }

  .folder-path {
    font-family: monospace;
    font-size: 0.85rem;
    word-break: break-all;
  }

  .tag {
    font-size: 0.7rem;
    padding: 0.15rem 0.4rem;
    border-radius: 4px;
    font-weight: 600;
  }

  .tag-warn {
    background: rgba(255, 171, 0, 0.12);
    color: var(--warning-amber);
    border: 1px solid rgba(255, 171, 0, 0.3);
  }

  .duplicate-list {
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
  }

  .duplicate-card {
    padding: 1rem;
    border-radius: 8px;
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid var(--border-color);
  }

  .duplicate-card h3 {
    margin-top: 0;
    font-size: 0.95rem;
    margin-bottom: 0.75rem;
  }

  .radio-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .radio-label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
    font-size: 0.85rem;
  }

  .file-path-radio {
    font-family: monospace;
    word-break: break-all;
  }

  .action-footer {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    gap: 1rem;
    margin-top: 1.5rem;
  }

  .results-grid {
    display: grid;
    grid-template-columns: 3fr 2fr;
    gap: 2rem;
    height: calc(100vh - 8rem);
  }

  .left-panel {
    display: flex;
    flex-direction: column;
    gap: 2rem;
    height: 100%;
  }

  .stats-card {
    padding: 1.5rem;
  }

  .progress-bar-container {
    margin-bottom: 1.5rem;
  }

  .progress-info {
    display: flex;
    justify-content: space-between;
    font-size: 0.85rem;
    color: var(--text-secondary);
    margin-bottom: 0.5rem;
  }

  .progress-track {
    height: 8px;
    background: rgba(255, 255, 255, 0.05);
    border-radius: 4px;
    overflow: hidden;
  }

  .progress-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--accent-blue), var(--accent-cyan));
    transition: width 0.4s ease-in-out;
  }

  .stats-counters {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 1rem;
  }

  .stat-box {
    padding: 1rem;
    border-radius: 8px;
    text-align: center;
    border: 1px solid var(--border-color);
  }

  .stat-box.success { background: rgba(0, 230, 118, 0.04); color: var(--success-green); border-color: rgba(0, 230, 118, 0.15); }
  .stat-box.partial { background: rgba(255, 171, 0, 0.04); color: var(--warning-amber); border-color: rgba(255, 171, 0, 0.15); }
  .stat-box.danger { background: rgba(255, 61, 0, 0.04); color: var(--danger-red); border-color: rgba(255, 61, 0, 0.15); }

  .stat-box .number { font-size: 1.75rem; font-weight: 700; display: block; }
  .stat-box .label { font-size: 0.75rem; color: var(--text-secondary); font-weight: 600; text-transform: uppercase; }

  .modules-list-card {
    flex: 1;
    padding: 1.5rem;
  }

  .list-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
  }

  .filters {
    display: flex;
    gap: 0.75rem;
  }

  .search-input {
    padding: 0.4rem 0.75rem;
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    color: #fff;
    font-size: 0.85rem;
  }

  .status-select {
    padding: 0.4rem 0.75rem;
    background: rgba(10, 14, 23, 0.9);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    color: #fff;
    font-size: 0.85rem;
  }

  .table-container {
    height: 35vh;
    overflow-y: auto;
  }

  .module-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
  }

  .module-table th, .module-table td {
    padding: 0.75rem 1rem;
    text-align: left;
    border-bottom: 1px solid var(--border-color);
  }

  .module-table th {
    color: var(--text-secondary);
    font-weight: 600;
  }

  .file-cell {
    font-family: monospace;
    color: var(--text-secondary);
    max-width: 250px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .badge {
    font-size: 0.7rem;
    font-weight: 700;
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    text-transform: uppercase;
  }

  .badge.status-validated { background: rgba(0, 230, 118, 0.15); color: var(--success-green); }
  .badge.status-partial { background: rgba(255, 171, 0, 0.15); color: var(--warning-amber); }
  .badge.status-failed { background: rgba(255, 61, 0, 0.15); color: var(--danger-red); }
  .badge.status-unvalidated { background: rgba(255, 255, 255, 0.08); color: var(--text-secondary); }
  .badge.status-completed { background: rgba(0, 230, 118, 0.15); color: var(--success-green); }
  .badge.status-running { background: rgba(33, 150, 243, 0.15); color: #2196f3; }
  .badge.status-pending { background: rgba(255, 255, 255, 0.08); color: var(--text-secondary); }
  .badge.risk-low { background: rgba(0, 230, 118, 0.15); color: var(--success-green); }
  .badge.risk-medium { background: rgba(255, 171, 0, 0.15); color: var(--warning-amber); }
  .badge.risk-high { background: rgba(255, 61, 0, 0.15); color: var(--danger-red); }
  .badge.risk-unknown { background: rgba(255, 255, 255, 0.08); color: var(--text-secondary); }

  .stats-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
  }

  .stats-header h2 {
    margin: 0;
  }

  .btn-sm {
    padding: 0.4rem 0.8rem;
    font-size: 0.8rem;
  }

  .console-header-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
  }

  .console-tabs {
    display: flex;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 2px;
  }

  .console-tab-btn {
    background: transparent;
    border: none;
    color: var(--text-muted);
    padding: 0.25rem 0.75rem;
    font-size: 0.75rem;
    cursor: pointer;
    border-radius: 4px;
    transition: all 0.2s ease;
  }

  .console-tab-btn:hover {
    color: var(--text-color);
    background: rgba(255, 255, 255, 0.03);
  }

  .console-tab-btn.active {
    background: var(--primary-color);
    color: #fff;
    font-weight: 500;
  }

  .empty-log {
    color: var(--text-muted);
    font-style: italic;
  }

  .console-card {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: 1.5rem;
  }

  .console-box {
    flex: 1;
    background: #05070c;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 1rem;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 0.8rem;
    overflow-y: auto;
    color: #c9d1d9;
    white-space: pre-wrap;
    height: 520px;
    max-height: 60vh;
  }

  .console-line {
    margin-bottom: 0.25rem;
    line-height: 1.4;
  }

  .console-input-area {
    display: flex;
    gap: 0.5rem;
    padding: 0.75rem;
    background: rgba(0, 0, 0, 0.25);
    border: 1px solid var(--border-color);
    border-top: none;
    border-bottom-left-radius: 8px;
    border-bottom-right-radius: 8px;
    margin-top: -1px;
  }

  .console-input-field {
    flex: 1;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    padding: 0.5rem;
    color: var(--text-primary);
    font-family: monospace;
  }

  .console-input-field:focus {
    outline: none;
    border-color: var(--accent-cyan);
  }

  .existing-run-alert {
    background: rgba(0, 112, 243, 0.08);
    border: 1px solid rgba(0, 112, 243, 0.25);
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
  }
  
  .existing-run-alert p {
    margin: 0.25rem 0 0 0;
    font-size: 0.85rem;
    color: var(--text-secondary);
  }

  .modal-backdrop {
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 1000;
  }

  .modal {
    max-width: 500px;
    width: 90%;
    border: 1px solid var(--border-color);
    padding: 2rem;
  }

  .modal h2 {
    margin-top: 0;
    font-size: 1.35rem;
    margin-bottom: 0.75rem;
  }

  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 1rem;
    margin-top: 1.5rem;
  }

  .clickable-badge {
    cursor: pointer;
    transition: transform 0.15s ease, box-shadow 0.15s ease;
  }

  .clickable-badge:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(255, 255, 255, 0.1);
    opacity: 0.9;
  }

  .detail-modal {
    max-width: 800px;
    width: 90%;
    max-height: 85vh;
    overflow-y: auto;
  }

  .detail-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 1rem;
    margin-bottom: 1.5rem;
  }

  .detail-header h2 {
    margin: 0;
    font-size: 1.25rem;
  }

  .close-btn {
    background: none;
    border: none;
    color: var(--text-secondary);
    font-size: 1.5rem;
    cursor: pointer;
    transition: color 0.2s;
  }

  .close-btn:hover {
    color: #fff;
  }

  .detail-body {
    text-align: left;
  }

  .detail-row {
    display: flex;
    gap: 1rem;
    margin-bottom: 1rem;
    align-items: center;
    font-size: 0.9rem;
  }

  .detail-label {
    font-weight: 600;
    color: var(--text-secondary);
    min-width: 100px;
  }

  .detail-value-path {
    font-family: monospace;
    color: var(--text-primary);
    background: rgba(255, 255, 255, 0.04);
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    word-break: break-all;
  }

  .detail-section {
    margin-top: 1.5rem;
    border-top: 1px solid var(--border-color);
    padding-top: 1.25rem;
  }

  .detail-section h3 {
    margin-top: 0;
    font-size: 1rem;
    margin-bottom: 0.75rem;
    color: var(--text-primary);
  }

  .stubs-list {
    margin: 0;
    padding-left: 1.25rem;
    color: var(--text-secondary);
  }

  .stubs-list li {
    margin-bottom: 0.25rem;
  }

  .stubs-list code {
    color: var(--accent-cyan);
    background: rgba(0, 223, 216, 0.05);
    padding: 0.1rem 0.3rem;
    border-radius: 3px;
  }

  .empty-text {
    color: var(--text-secondary);
    font-style: italic;
    margin: 0;
    font-size: 0.85rem;
  }

  .tool-error-box {
    margin-top: 1rem;
    border: 1px solid var(--border-color);
    border-radius: 6px;
    overflow: hidden;
  }

  .tool-error-header {
    background: rgba(255, 255, 255, 0.03);
    padding: 0.5rem 1rem;
    font-size: 0.8rem;
    font-weight: 600;
    text-transform: uppercase;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border-color);
  }

  .tool-error-pre {
    margin: 0;
    padding: 1rem;
    font-family: monospace;
    font-size: 0.8rem;
    overflow-x: auto;
    background: #05070c;
    color: #f8f8f2;
    white-space: pre-wrap;
    max-height: 250px;
    overflow-y: auto;
  }
  /* Sidebar and split layout styles */
  .dashboard-layout {
    display: flex;
    gap: 1.5rem;
    height: calc(100vh - 100px);
    width: 100%;
    margin-top: 1rem;
    box-sizing: border-box;
  }

  .sidebar {
    width: 250px;
    background: rgba(16, 24, 40, 0.45);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 1.25rem;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    backdrop-filter: blur(12px);
    flex-shrink: 0;
  }

  .sidebar-section {
    margin-bottom: 1.5rem;
  }

  .sidebar-section h3 {
    font-size: 0.75rem;
    text-transform: uppercase;
    color: var(--text-secondary);
    letter-spacing: 0.05em;
    margin-top: 0;
    margin-bottom: 0.75rem;
  }

  .sidebar-item {
    width: 100%;
    background: none;
    border: none;
    text-align: left;
    color: var(--text-secondary);
    padding: 0.75rem 1rem;
    border-radius: 8px;
    font-size: 0.85rem;
    cursor: pointer;
    transition: all 0.2s ease;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 0.4rem;
  }

  .sidebar-item:hover:not(:disabled) {
    background: rgba(255, 255, 255, 0.04);
    color: var(--text-primary);
  }

  .sidebar-item.active {
    background: rgba(0, 112, 243, 0.15);
    border: 1px solid rgba(0, 112, 243, 0.3);
    color: #fff;
    font-weight: 500;
  }

  .sidebar-item:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .badge-lock {
    margin-left: auto;
    font-size: 0.75rem;
  }

  .sidebar-footer {
    border-top: 1px solid var(--border-color);
    padding-top: 1rem;
    margin-top: auto;
  }

  .main-workspace {
    flex: 1;
    height: 100%;
    overflow-y: auto;
    min-width: 0;
  }

  /* Phase 0.3 Context panel styles */
  .context-panel {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: 1.5rem;
    box-sizing: border-box;
  }

  .tab-buttons {
    display: flex;
    gap: 0.5rem;
    background: rgba(0, 0, 0, 0.2);
    padding: 0.3rem;
    border-radius: 8px;
    border: 1px solid var(--border-color);
  }

  .tab-btn {
    background: none;
    border: none;
    color: var(--text-secondary);
    padding: 0.4rem 0.8rem;
    border-radius: 6px;
    font-size: 0.8rem;
    cursor: pointer;
    transition: all 0.2s;
  }

  .tab-btn:hover {
    color: var(--text-primary);
  }

  .tab-btn.active {
    background: rgba(255, 255, 255, 0.08);
    color: #fff;
    font-weight: 500;
  }

  .context-content-grid {
    display: flex;
    gap: 1.5rem;
    margin-top: 1.5rem;
    flex: 1;
    min-height: 0;
  }

  .context-main-view {
    flex: 1.3;
    background: rgba(0, 0, 0, 0.15);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 1.25rem;
    height: 100%;
  }

  .context-detail-panel {
    flex: 1;
    background: rgba(16, 24, 40, 0.35);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
    overflow-y: auto;
    height: 100%;
  }

  .tree-nodes-list {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    margin-top: 1rem;
  }

  .tree-node-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.6rem;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.85rem;
    transition: all 0.15s;
    border: 1px solid transparent;
  }

  .tree-node-item:hover {
    background: rgba(255, 255, 255, 0.03);
  }

  .tree-node-item.selected {
    background: rgba(0, 223, 216, 0.08);
    border-color: rgba(0, 223, 216, 0.25);
    color: var(--accent-cyan);
  }

  .tree-connector {
    color: var(--text-secondary);
    opacity: 0.4;
    font-family: monospace;
  }

  .inst-name {
    color: var(--text-secondary);
    font-size: 0.75rem;
    font-style: italic;
  }

  .secret-code {
    color: #ff79c6;
    background: rgba(255, 121, 198, 0.08);
    padding: 0.15rem 0.4rem;
    border-radius: 4px;
    font-family: monospace;
    font-size: 0.85rem;
  }

  .reason-tag {
    color: var(--warning-amber);
    background: rgba(255, 171, 0, 0.08);
    padding: 0.15rem 0.4rem;
    border-radius: 4px;
    font-size: 0.75rem;
  }

  .profile-field {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    padding-bottom: 0.75rem;
  }

  .profile-label {
    font-size: 0.75rem;
    text-transform: uppercase;
    color: var(--text-secondary);
    letter-spacing: 0.03em;
  }

  .summary-box {
    background: rgba(0, 0, 0, 0.25);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 1rem;
    font-size: 0.85rem;
    line-height: 1.5;
    color: #e1e4e8;
    white-space: pre-wrap;
  }

  .secrets-bullet-list {
    margin: 0;
    padding-left: 1.2rem;
  }

  .secrets-bullet-list li {
    margin-bottom: 0.5rem;
    font-size: 0.85rem;
  }

  .sig-meta {
    font-size: 0.75rem;
    color: var(--text-secondary);
    margin-left: 0.4rem;
  }

  .clickable-row {
    cursor: pointer;
    transition: background 0.15s;
  }

  .clickable-row:hover {
    background: rgba(255, 255, 255, 0.02) !important;
  }

  .empty-detail-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    color: var(--text-secondary);
    height: 100%;
    gap: 1rem;
  }

  .empty-detail-state .icon {
    font-size: 2.5rem;
    opacity: 0.5;
  }

  .empty-detail-state p {
    font-size: 0.85rem;
    max-width: 250px;
    line-height: 1.4;
  }

  /* Locked Panel Styles */
  .locked-panel {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    padding: 3rem;
  }

  .locked-card-content {
    text-align: center;
    max-width: 400px;
  }

  .locked-icon {
    font-size: 3.5rem;
    display: block;
    margin-bottom: 1.5rem;
    animation: pulse 2s infinite ease-in-out;
  }

  .w-100 {
    width: 100%;
  }

  /* Trust boundaries badges styling */
  .badge.trust-high-trust {
    background: rgba(0, 230, 118, 0.12);
    border: 1px solid rgba(0, 230, 118, 0.3);
    color: var(--success-green);
  }
  .badge.trust-internal-logic {
    background: rgba(0, 112, 243, 0.12);
    border: 1px solid rgba(0, 112, 243, 0.3);
    color: #4fc3f7;
  }
  .badge.trust-external-io {
    background: rgba(255, 171, 0, 0.12);
    border: 1px solid rgba(255, 171, 0, 0.3);
    color: var(--warning-amber);
  }

  @keyframes pulse {
    0%, 100% { opacity: 0.6; transform: scale(1); }
    50% { opacity: 1; transform: scale(1.05); }
  }

  /* Stats grid for Synthesis */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 1rem;
    margin-top: 0.5rem;
  }
  .stat-card {
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 6px;
    padding: 0.8rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
  }
  .stat-num {
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--accent-color, #58a6ff);
  }
  .stat-label {
    font-size: 0.75rem;
    color: var(--text-secondary);
    margin-top: 0.2rem;
  }
  .selected-row {
    background: rgba(88, 166, 255, 0.1) !important;
  }
</style>
