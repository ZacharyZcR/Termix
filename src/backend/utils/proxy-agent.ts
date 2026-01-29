import { HttpsProxyAgent } from "https-proxy-agent";
import type { Agent } from "http";

/**
 * Creates a proxy agent from environment variables for HTTP/HTTPS requests.
 * Supports http_proxy, https_proxy, HTTP_PROXY, and HTTPS_PROXY.
 * Respects no_proxy/NO_PROXY exclusion lists.
 * Returns undefined if no proxy is configured or the target URL is excluded.
 */
export function getProxyAgent(targetUrl?: string): Agent | undefined {
  const noProxy = process.env.no_proxy || process.env.NO_PROXY || "";
  const noProxyList = noProxy.split(",").map((s) => s.trim().toLowerCase());

  if (targetUrl) {
    try {
      const url = new URL(targetUrl);
      const hostname = url.hostname.toLowerCase();

      for (const noProxyEntry of noProxyList) {
        if (!noProxyEntry) continue;

        // Handle leading dot notation (e.g., .example.com matches sub.example.com)
        const normalizedEntry = noProxyEntry.startsWith(".")
          ? noProxyEntry.slice(1)
          : noProxyEntry;

        // Handle wildcard patterns (e.g., *.example.com)
        const entryWithoutWildcard = normalizedEntry.startsWith("*.")
          ? normalizedEntry.slice(2)
          : normalizedEntry;

        if (
          hostname === entryWithoutWildcard ||
          hostname.endsWith(`.${entryWithoutWildcard}`)
        ) {
          return undefined;
        }
      }
    } catch {
      // Invalid URL, continue with proxy
    }
  }

  const proxyUrl =
    process.env.https_proxy ||
    process.env.HTTPS_PROXY ||
    process.env.http_proxy ||
    process.env.HTTP_PROXY;

  if (!proxyUrl) {
    return undefined;
  }

  return new HttpsProxyAgent(proxyUrl);
}
