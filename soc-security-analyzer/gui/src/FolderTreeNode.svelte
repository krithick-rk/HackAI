<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  export let node: any;
  export let excludedFolders: Set<string>;
  export let expandedNodes: Set<string>;
  export let hideUnselected: boolean = false;

  const dispatch = createEventDispatcher();

  $: isChecked = !excludedFolders.has(node.path);
  $: isExpanded = expandedNodes.has(node.path);

  function checkHasSelected(n: any, excluded: Set<string>): boolean {
    if (!excluded.has(n.path)) return true;
    if (n.children) {
      for (const child of n.children) {
        if (checkHasSelected(child, excluded)) return true;
      }
    }
    return false;
  }

  $: hasSelected = checkHasSelected(node, excludedFolders);

  function handleCheckChange(e: Event) {
    const target = e.target as HTMLInputElement;
    dispatch('toggleCheck', { node, checked: target.checked });
  }

  function handleExpandToggle() {
    dispatch('toggleExpand', { path: node.path });
  }
</script>

{#if !hideUnselected || hasSelected}
  <div class="tree-node-item">
    <div class="tree-node-row">
      {#if node.children.length > 0}
        <button 
          type="button"
          class="expand-arrow {isExpanded ? 'is-expanded' : ''}" 
          on:click={handleExpandToggle}
          aria-label={isExpanded ? 'Collapse folder' : 'Expand folder'}
        >
          ▶
        </button>
      {:else}
        <span class="expand-placeholder"></span>
      {/if}

      <label class="tree-label">
        <input 
          type="checkbox" 
          checked={isChecked} 
          on:change={handleCheckChange} 
        />
        <span class="folder-name">{node.name}</span>
        {#if node.isSuggestedExclusion}
          <span class="tag tag-warn">Simulation/Testbench Candidate</span>
        {/if}
      </label>
    </div>

    {#if node.children.length > 0 && isExpanded}
      <div class="tree-children">
        {#each node.children as child}
          <svelte:self 
            node={child} 
            {excludedFolders} 
            {expandedNodes} 
            {hideUnselected}
            on:toggleCheck 
            on:toggleExpand 
          />
        {/each}
      </div>
    {/if}
  </div>
{/if}

<style>
  .tree-node-item {
    margin-left: 0;
    text-align: left;
  }

  .tree-node-row {
    display: flex;
    align-items: center;
    padding: 0.25rem 0;
    gap: 0.5rem;
  }

  .expand-arrow {
    background: none;
    border: none;
    color: var(--text-secondary);
    font-size: 0.65rem;
    cursor: pointer;
    padding: 0.2rem;
    width: 20px;
    height: 20px;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: transform 0.15s ease;
  }

  .expand-arrow.is-expanded {
    transform: rotate(90deg);
  }

  .expand-placeholder {
    width: 20px;
    height: 20px;
  }

  .tree-label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
    font-size: 0.9rem;
    user-select: none;
  }

  .folder-name {
    color: var(--text-primary);
  }

  .tree-children {
    padding-left: 1.5rem;
    border-left: 1px dashed rgba(255, 255, 255, 0.1);
    margin-left: 0.6rem;
  }

  .tag {
    font-size: 0.7rem;
    padding: 0.1rem 0.35rem;
    border-radius: 4px;
    font-weight: 500;
  }

  .tag-warn {
    background: rgba(255, 170, 0, 0.1);
    color: #ffaa00;
    border: 1px solid rgba(255, 170, 0, 0.2);
  }
</style>
