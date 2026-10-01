import { writable, derived } from 'svelte/store';

export interface RouteMatch {
  name: string;
  path: string;
  params: Record<string, string>;
  query: Record<string, string>;
}

// Current browser pathname store
export const currentPath = writable<string>(
  typeof window !== 'undefined' ? window.location.pathname : '/'
);

// Route definition table
interface RouteDef {
  name: string;
  pattern: RegExp;
  paramNames: string[];
}

function compileRoute(pattern: string, name: string): RouteDef {
  const paramNames: string[] = [];
  const regexPattern = pattern
    .replace(/:([a-zA-Z0-9_]+)/g, (_, paramName) => {
      paramNames.push(paramName);
      return '([^/]+)';
    })
    .replace(/\//g, '\\/');

  return {
    name,
    pattern: new RegExp(`^${regexPattern}$`),
    paramNames
  };
}

const routes: RouteDef[] = [
  compileRoute('/', 'root'),
  compileRoute('/dashboard', 'dashboard'),
  compileRoute('/projects', 'projects'),
  compileRoute('/projects/:id', 'project_detail'),
  compileRoute('/projects/:id/discovery', 'project_discovery'),
  compileRoute('/projects/:id/modules', 'project_modules'),
  compileRoute('/projects/:id/analyze', 'project_analyze'),
  compileRoute('/findings', 'findings'),
  compileRoute('/findings/:id', 'finding_detail'),
  compileRoute('/reports', 'reports'),
  compileRoute('/settings', 'settings'),
  compileRoute('/validation', 'validation'),
  compileRoute('/context', 'context'),
  compileRoute('/synthesis', 'synthesis'),
  compileRoute('/fuzzing', 'fuzzing'),
  compileRoute('/benchmark', 'benchmark'),
];

export function parseQuery(queryString: string): Record<string, string> {
  const query: Record<string, string> = {};
  if (!queryString) return query;
  const search = queryString.startsWith('?') ? queryString.slice(1) : queryString;
  for (const pair of search.split('&')) {
    if (!pair) continue;
    const [k, v] = pair.split('=');
    query[decodeURIComponent(k)] = decodeURIComponent(v || '');
  }
  return query;
}

export const currentRoute = derived(currentPath, ($path): RouteMatch => {
  const cleanPath = $path.replace(/\/+$/, '') || '/';
  const queryString = typeof window !== 'undefined' ? window.location.search : '';
  const query = parseQuery(queryString);

  for (const r of routes) {
    const match = cleanPath.match(r.pattern);
    if (match) {
      const params: Record<string, string> = {};
      r.paramNames.forEach((name, i) => {
        params[name] = decodeURIComponent(match[i + 1]);
      });
      return {
        name: r.name,
        path: cleanPath,
        params,
        query
      };
    }
  }

  // Fallback for unknown frontend routes
  return {
    name: 'dashboard',
    path: cleanPath,
    params: {},
    query
  };
});

/**
 * Navigate to a frontend route using HTML5 History API.
 */
export function navigate(to: string, { replace = false }: { replace?: boolean } = {}) {
  if (typeof window === 'undefined') return;

  const [pathPart, queryPart] = to.split('?');
  const targetPath = pathPart.replace(/\/+$/, '') || '/';
  const fullTarget = queryPart ? `${targetPath}?${queryPart}` : targetPath;

  if (replace) {
    window.history.replaceState({ path: fullTarget }, '', fullTarget);
  } else {
    window.history.pushState({ path: fullTarget }, '', fullTarget);
  }

  currentPath.set(targetPath);
}

/**
 * Initialize router popstate listener.
 */
export function initRouter() {
  if (typeof window === 'undefined') return;

  const onPopState = () => {
    currentPath.set(window.location.pathname);
  };

  window.addEventListener('popstate', onPopState);

  // Initial synchronization
  currentPath.set(window.location.pathname);

  return () => {
    window.removeEventListener('popstate', onPopState);
  };
}
