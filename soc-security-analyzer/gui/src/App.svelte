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
      } else {
        excludedFolders = new Set(preScanData.suggested_exclusions);
      }
      // Pre-populate duplicate choices
      if (preScanData.saved_duplicates) {
        resolvedDuplicates = { ...preScanData.saved_duplicates };
      } else {
        resolvedDuplicates = {};
        preScanData.duplicates.forEach(d => {
          resolvedDuplicates[d.module] = d.paths[0];
        });
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
        logs: ["Clearing old workspace and restarting pipeline..."]
      };
      modulesList = [];

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
        logs: ["Clearing workspace and restarting pipeline..."]
      };
      modulesList = [];

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

  onMount(() => {
    // Check if a run is already active
    pollStatus();
  });

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
              <button class="btn btn-secondary btn-sm" on:click={() => step = 'results'}>Load Previous Results</button>
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
    {/if}

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
            <button class="btn btn-secondary" on:click={() => step = 'setup'}>Back</button>
            <button class="btn btn-primary" on:click={handleStartRun}>Launch Pipeline</button>
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
                <div style="display: flex; gap: 0.5rem;">
                  <button class="btn btn-secondary btn-sm" on:click={() => step = 'config'}>Configure</button>
                  <button class="btn btn-primary btn-sm" on:click={handleReRun}>Clean & Re-run</button>
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
                            on:click={() => selectedModuleForDetail = mod}
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
          <h2>Console Execution Stream</h2>
          <div class="console-box" id="console" bind:this={consoleElement}>
            {#each runStatus.logs as log}
              <div class="console-line">{log}</div>
            {/each}
          </div>
        </section>
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
    <div class="modal-backdrop" on:click={() => selectedModuleForDetail = null}>
      <div class="modal card glass detail-modal" on:click|stopPropagation>
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
</style>
