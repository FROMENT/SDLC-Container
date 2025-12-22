import { Base64 } from 'js-base64';

export interface GitHubConfig {
  token: string;
  owner: string;
  repo: string;
  path: string;
  branch: string;
}

export interface AppState {
  activePhase: string;
  activeModuleId: string;
  viewCounts: Record<string, number>;
  theme: string;
  lang: string;
  lastUpdated: number;
}

export const saveToGitHub = async (config: GitHubConfig, data: AppState): Promise<void> => {
  if (!config.token || !config.owner || !config.repo || !config.path) {
    throw new Error("Missing GitHub configuration");
  }

  const content = JSON.stringify(data, null, 2);
  const encodedContent = Base64.encode(content);
  
  // 1. Get current SHA (if exists) to allow updates
  let sha: string | undefined;
  try {
    const getUrl = `https://api.github.com/repos/${config.owner}/${config.repo}/contents/${config.path}?ref=${config.branch}`;
    const getRes = await fetch(getUrl, {
      headers: {
        Authorization: `Bearer ${config.token}`,
        Accept: 'application/vnd.github.v3+json'
      }
    });
    if (getRes.ok) {
      const json = await getRes.json();
      sha = json.sha;
    }
  } catch (e) {
    // Ignore, assume file doesn't exist or other error we can try to overwrite
  }

  // 2. PUT file
  const putUrl = `https://api.github.com/repos/${config.owner}/${config.repo}/contents/${config.path}`;
  const putRes = await fetch(putUrl, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${config.token}`,
      Accept: 'application/vnd.github.v3+json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      message: `Update progress: ${new Date().toISOString()}`,
      content: encodedContent,
      branch: config.branch,
      sha: sha
    })
  });

  if (!putRes.ok) {
    const err = await putRes.json();
    throw new Error(err.message || "Failed to save to GitHub");
  }
};

export const loadFromGitHub = async (config: GitHubConfig): Promise<AppState | null> => {
  if (!config.token || !config.owner || !config.repo || !config.path) {
     return null;
  }

  try {
    const url = `https://api.github.com/repos/${config.owner}/${config.repo}/contents/${config.path}?ref=${config.branch}`;
    const res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${config.token}`,
        Accept: 'application/vnd.github.v3+json'
      }
    });

    if (!res.ok) return null;

    const json = await res.json();
    const decoded = Base64.decode(json.content);
    return JSON.parse(decoded);
  } catch (e) {
    console.error("Error loading from GitHub", e);
    return null;
  }
};