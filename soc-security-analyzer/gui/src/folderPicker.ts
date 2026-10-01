/**
 * Unified Folder Picker Utility for SoC Security Analyzer.
 * Supports:
 * 1. Native OS directory picker bridge via backend (/api/projects/select-folder).
 * 2. Modern browser File System Access API (window.showDirectoryPicker).
 * 3. Fallback browser directory upload (<input type="file" webkitdirectory>).
 */

export interface DirectorySelectionResult {
  status: 'selected' | 'cancelled' | 'error';
  path?: string;
  name?: string;
  fileCount?: number;
  error?: string;
}

/**
 * Attempt to select a directory using the native host OS bridge.
 */
async function selectViaNativeBridge(title?: string): Promise<DirectorySelectionResult> {
  try {
    const res = await fetch('/api/projects/select-folder', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: title || 'Select Repository / Project Directory' })
    });

    if (!res.ok) {
      return { status: 'error', error: `Native bridge HTTP ${res.status}` };
    }

    const data = await res.json();
    if (data.status === 'ok' && data.path) {
      return {
        status: 'selected',
        path: data.path,
        name: data.name || data.path.split('/').pop()
      };
    } else if (data.status === 'cancelled') {
      return { status: 'cancelled' };
    } else {
      return { status: 'error', error: data.detail || 'Native bridge unsupported' };
    }
  } catch (err: any) {
    return { status: 'error', error: err.message || 'Bridge connection failed' };
  }
}

/**
 * Upload collected directory files to backend workspace.
 */
async function uploadDirectoryFiles(
  projectName: string,
  files: Array<{ file: File; relPath: string }>
): Promise<DirectorySelectionResult> {
  if (!files || files.length === 0) {
    return { status: 'error', error: 'No files found in selected directory.' };
  }

  const formData = new FormData();
  formData.append('project_name', projectName);

  for (const item of files) {
    formData.append('files', item.file);
    formData.append('paths', item.relPath);
  }

  const res = await fetch('/api/projects/upload-directory', {
    method: 'POST',
    body: formData
  });

  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    return { status: 'error', error: errData.detail || `Upload failed with HTTP ${res.status}` };
  }

  const data = await res.json();
  return {
    status: 'selected',
    path: data.repository_path,
    name: data.project_name || projectName,
    fileCount: data.saved_files_count
  };
}

/**
 * Select directory using browser File System Access API (showDirectoryPicker).
 */
async function selectViaFileSystemAccessApi(projectName: string): Promise<DirectorySelectionResult> {
  if (typeof (window as any).showDirectoryPicker !== 'function') {
    return { status: 'error', error: 'File System Access API not supported' };
  }

  try {
    const dirHandle = await (window as any).showDirectoryPicker({
      mode: 'read'
    });

    if (!dirHandle) {
      return { status: 'cancelled' };
    }

    // Collect RTL and project files recursively
    const collectedFiles: Array<{ file: File; relPath: string }> = [];

    async function walk(handle: any, currentPath: string) {
      for await (const entry of handle.values()) {
        const entryPath = currentPath ? `${currentPath}/${entry.name}` : entry.name;
        if (entry.kind === 'file') {
          // Filter for relevant files or include all
          const file = await entry.getFile();
          collectedFiles.push({ file, relPath: entryPath });
        } else if (entry.kind === 'directory') {
          // Avoid huge hidden git dirs if possible, or include
          if (entry.name !== '.git' && entry.name !== 'node_modules') {
            await walk(entry, entryPath);
          }
        }
      }
    }

    await walk(dirHandle, dirHandle.name);

    if (collectedFiles.length === 0) {
      return {
        status: 'selected',
        path: `workspace/projects/${projectName || dirHandle.name}/repository`,
        name: dirHandle.name,
        fileCount: 0
      };
    }

    return await uploadDirectoryFiles(projectName || dirHandle.name, collectedFiles);
  } catch (err: any) {
    if (err.name === 'AbortError') {
      return { status: 'cancelled' };
    }
    return { status: 'error', error: err.message };
  }
}

/**
 * Select directory using HTML input webkitdirectory fallback.
 */
function selectViaInputFallback(projectName: string): Promise<DirectorySelectionResult> {
  return new Promise((resolve) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.multiple = true;
    (input as any).webkitdirectory = true;
    input.style.display = 'none';

    let settled = false;

    input.onchange = async () => {
      settled = true;
      const fileList = input.files;
      if (!fileList || fileList.length === 0) {
        document.body.removeChild(input);
        resolve({ status: 'cancelled' });
        return;
      }

      const collected: Array<{ file: File; relPath: string }> = [];
      let rootDirName = '';

      for (let i = 0; i < fileList.length; i++) {
        const file = fileList[i];
        const relPath = (file as any).webkitRelativePath || file.name;
        if (!rootDirName && relPath.includes('/')) {
          rootDirName = relPath.split('/')[0];
        }
        collected.push({ file, relPath });
      }

      document.body.removeChild(input);
      const res = await uploadDirectoryFiles(projectName || rootDirName, collected);
      resolve(res);
    };

    // If window regains focus without change event, handle cancel
    window.addEventListener(
      'focus',
      () => {
        setTimeout(() => {
          if (!settled && input.parentNode) {
            document.body.removeChild(input);
            resolve({ status: 'cancelled' });
          }
        }, 800);
      },
      { once: true }
    );

    document.body.appendChild(input);
    input.click();
  });
}

/**
 * Main folder selection entrypoint.
 * Automatically tries:
 * 1. Native system bridge (for seamless local development / desktop experience).
 * 2. Browser showDirectoryPicker (modern browsers).
 * 3. input webkitdirectory (universal browser fallback).
 */
export async function pickProjectDirectory(
  projectName: string = 'default_project',
  options: { preferBrowser?: boolean; title?: string } = {}
): Promise<DirectorySelectionResult> {
  // 1. Unless browser is explicitly preferred, try local host OS bridge first
  if (!options.preferBrowser) {
    const nativeRes = await selectViaNativeBridge(options.title);
    if (nativeRes.status === 'selected' || nativeRes.status === 'cancelled') {
      return nativeRes;
    }
    // If nativeRes.status === 'error', gracefully fallback to browser selection
    console.info('Native bridge not available, falling back to browser directory picker:', nativeRes.error);
  }

  // 2. Try File System Access API
  if (typeof (window as any).showDirectoryPicker === 'function') {
    const fsaRes = await selectViaFileSystemAccessApi(projectName);
    if (fsaRes.status === 'selected' || fsaRes.status === 'cancelled') {
      return fsaRes;
    }
  }

  // 3. Fallback to webkitdirectory file input
  return await selectViaInputFallback(projectName);
}
