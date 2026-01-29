import { HttpsProxyAgent } from "https-proxy-agent";
import type { Agent } from "http";

/**
 * Creates an HTTPS proxy agent from environment variables.
 * Supports http_proxy, https_proxy, HTTP_PROXY, and HTTPS_PROXY.
 * Returns undefined if no proxy is configured.
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
        if (hostname === noProxyEntry || hostname.endsWith(`.${noProxyEntry}`)) {
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
