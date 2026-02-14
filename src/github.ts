/**
 * GitHub repository health checker for npx-ray.
 *
 * Fetches repository metadata from the GitHub API to assess the health
 * and trustworthiness of a package's source repository. Checks stars,
 * forks, archive status, and whether the npm publisher matches the
 * GitHub owner.
 */

import type { GitHubHealth } from './types.js';

const GITHUB_API = 'https://api.github.com';
const USER_AGENT = 'npx-ray/1.0.0';

/**
 * Parse a GitHub repository URL into an owner/repo pair.
 *
 * Supports these formats:
 *   - https://github.com/owner/repo
 *   - https://github.com/owner/repo.git
 *   - git+https://github.com/owner/repo.git
 *   - git://github.com/owner/repo.git
 *   - github:owner/repo
 *
 * @returns `{ owner, repo }` or `null` if the URL cannot be parsed.
 */
export function parseGitHubUrl(repoUrl: string): { owner: string; repo: string } | null {
  // Normalize: strip trailing slashes and whitespace
  let url = repoUrl.trim().replace(/\/+$/, '');

  // Handle `github:owner/repo` shorthand
  if (url.startsWith('github:')) {
    const path = url.slice('github:'.length);
    const parts = path.split('/');
    if (parts.length >= 2) {
      return { owner: parts[0], repo: parts[1].replace(/\.git$/, '') };
    }
    return null;
  }

  // Strip `git+` prefix
  if (url.startsWith('git+')) {
    url = url.slice(4);
  }

  // Handle `git://` by converting to `https://`
  if (url.startsWith('git://')) {
    url = 'https://' + url.slice(6);
  }

  // Now we should have an https:// URL
  try {
    const parsed = new URL(url);
    if (parsed.hostname !== 'github.com') {
      return null;
    }

    // pathname is /owner/repo or /owner/repo.git
    const segments = parsed.pathname.split('/').filter(Boolean);
    if (segments.length < 2) {
      return null;
    }

    const owner = segments[0];
    const repo = segments[1].replace(/\.git$/, '');
    return { owner, repo };
  } catch {
    return null;
  }
}

/**
 * Build a "not found" health result with zeroed fields.
 */
function notFound(): GitHubHealth {
  return {
    found: false,
    fullName: '',
    stars: 0,
    forks: 0,
    openIssues: 0,
    license: '',
    createdAt: '',
    lastPush: '',
    archived: false,
    publisherMatchesOwner: false,
  };
}

/**
 * Check the health of a GitHub repository linked to an npm package.
 *
 * Makes an unauthenticated request to the GitHub API. Rate-limited to
 * 60 requests/hour without a token, which is sufficient for single-package
 * scans.
 *
 * @param repoUrl      - Repository URL from the npm package metadata.
 * @param npmPublisher  - The npm publisher username (used to check owner match).
 * @returns GitHub health information, or a `{ found: false }` result on failure.
 */
export async function checkGitHubHealth(
  repoUrl: string,
  npmPublisher: string,
): Promise<GitHubHealth> {
  const parsed = parseGitHubUrl(repoUrl);
  if (!parsed) {
    return notFound();
  }

  const { owner, repo } = parsed;

  try {
    const response = await fetch(`${GITHUB_API}/repos/${owner}/${repo}`, {
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'application/vnd.github.v3+json',
      },
    });

    if (!response.ok) {
      return notFound();
    }

    const data = (await response.json()) as Record<string, unknown>;

    // Extract license SPDX ID
    let license = '';
    const licenseObj = data.license as Record<string, unknown> | null;
    if (licenseObj && typeof licenseObj.spdx_id === 'string') {
      license = licenseObj.spdx_id;
    }

    // Compare npm publisher against GitHub owner (case-insensitive)
    const publisherMatchesOwner =
      npmPublisher.toLowerCase() === owner.toLowerCase();

    return {
      found: true,
      fullName: (data.full_name as string) || `${owner}/${repo}`,
      stars: (data.stargazers_count as number) || 0,
      forks: (data.forks_count as number) || 0,
      openIssues: (data.open_issues_count as number) || 0,
      license,
      createdAt: (data.created_at as string) || '',
      lastPush: (data.pushed_at as string) || '',
      archived: (data.archived as boolean) || false,
      publisherMatchesOwner,
    };
  } catch {
    return notFound();
  }
}
