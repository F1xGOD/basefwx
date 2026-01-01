const repo = "F1xGOD/basefwx";
const releaseApi = `https://api.github.com/repos/${repo}/releases/latest`;
let latestReleaseTag = "";
const assetMap = {
  linux: {
    bin: "basefwx-linux",
    sha256: "basefwx-linux.sha256",
    md5: "basefwx-linux.md5",
    sig: "basefwx-linux.sig"
  },
  windows: {
    bin: "basefwx-windows.exe",
    sha256: "basefwx-windows.exe.sha256",
    md5: "basefwx-windows.exe.md5",
    sig: "basefwx-windows.exe.sig"
  },
  mac: {
    bin: "basefwx-mac",
    sha256: "basefwx-mac.sha256",
    md5: "basefwx-mac.md5",
    sig: "basefwx-mac.sig"
  }
};

const setText = (id, value) => {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = value;
  }
};

const getAssetBase = () => {
  const base = document.documentElement.dataset.assetBase;
  return base || "assets/";
};

const initBrandMask = () => {
  if (!window.CSS || !CSS.supports) {
    return;
  }
  const base = getAssetBase();
  const maskUrl = new URL(`${base}basefwx-white.svg`, window.location.href).toString();
  const supportsMask =
    CSS.supports("mask-image", `url(\"${maskUrl}\")`) ||
    CSS.supports("-webkit-mask-image", `url(\"${maskUrl}\")`);
  if (!supportsMask) {
    return;
  }
  const img = new Image();
  img.onload = () => document.documentElement.classList.add("mask-ready");
  img.src = maskUrl;
};

const setLink = (selector, url) => {
  const el = document.querySelector(selector);
  if (!el) return;
  if (url) {
    el.href = url;
    el.setAttribute("target", "_blank");
    el.setAttribute("rel", "noopener");
    el.classList.remove("disabled");
  } else {
    el.href = "#";
  }
};

const parseHash = (content) => {
  const parts = content.trim().split(/\s+/);
  return parts.length ? parts[0] : "";
};

const fillHash = async (selector, urls) => {
  const el = document.querySelector(`[data-hash="${selector}"]`);
  if (!el) return;
  const candidates = Array.isArray(urls) ? urls.filter(Boolean) : urls ? [urls] : [];
  if (!candidates.length) {
    el.textContent = "Hash not available";
    return;
  }
  for (const url of candidates) {
    try {
      const resp = await fetch(url);
      if (!resp.ok) {
        continue;
      }
      const text = await resp.text();
      el.textContent = parseHash(text);
      return;
    } catch (err) {
      continue;
    }
  }
  el.textContent = "Unable to load hash";
};

const getResultsBases = (tag) => {
  const mainBase = `https://raw.githubusercontent.com/${repo}/main/results`;
  const tagBase = tag ? `https://raw.githubusercontent.com/${repo}/results/${tag}/results` : "";
  return {
    primary: tagBase || mainBase,
    fallback: mainBase
  };
};

const loadRelease = async () => {
  try {
    const response = await fetch(releaseApi);
    if (!response.ok) {
      throw new Error("release fetch failed");
    }
    const data = await response.json();
    latestReleaseTag = data.tag_name || "";
    const assets = data.assets || [];
    const assetLookup = new Map(assets.map((asset) => [asset.name, asset]));
    const resultsBases = getResultsBases(latestReleaseTag);
    const localResultsBase = new URL("results/", window.location.href).toString();

    setText("release-version", data.name || data.tag_name || "Latest release");
    setText(
      "release-date",
      data.published_at ? new Date(data.published_at).toLocaleDateString() : "Release date pending"
    );
    setText("release-assets", `${assets.length} assets`);
    setLink("#release-link", data.html_url);
    setLink("#download-cta", data.html_url);

    Object.entries(assetMap).forEach(([key, values]) => {
      const binAsset = assetLookup.get(values.bin);
      const sigAsset = assetLookup.get(values.sig);
      setLink(`[data-download="${key}"]`, binAsset ? binAsset.browser_download_url : null);
      setLink(`[data-asset="${key}.sig"]`, sigAsset ? sigAsset.browser_download_url : null);
      fillHash(`${key}.sha256`, [
        `${resultsBases.primary}/${values.sha256}`,
        `${resultsBases.fallback}/${values.sha256}`,
        `${localResultsBase}${values.sha256}`
      ]);
      fillHash(`${key}.md5`, [
        `${resultsBases.primary}/${values.md5}`,
        `${resultsBases.fallback}/${values.md5}`,
        `${localResultsBase}${values.md5}`
      ]);
    });
  } catch (err) {
    setText("release-version", "Release data unavailable");
    setText("release-date", "Check GitHub for details");
    setText("release-assets", "-");
  }
};

const loadVirusTotal = async () => {
  const summary = document.getElementById("vt-summary");
  const tableBody = document.querySelector("#vt-table tbody");
  try {
    const resultsBases = getResultsBases(latestReleaseTag);
    const localBase = new URL("results/", window.location.href).toString();
    const candidates = [
      `${resultsBases.primary}/virustotal-latest.json`,
      latestReleaseTag ? `${resultsBases.primary}/virustotal-${latestReleaseTag}.json` : "",
      `${resultsBases.fallback}/virustotal-latest.json`,
      latestReleaseTag ? `${resultsBases.fallback}/virustotal-${latestReleaseTag}.json` : "",
      `${localBase}virustotal-latest.json`
    ].filter(Boolean);

    let resultsUrl = "";
    let response = null;
    for (const candidate of candidates) {
      const attempt = await fetch(candidate);
      if (attempt.ok) {
        resultsUrl = candidate;
        response = attempt;
        break;
      }
    }
    if (!response) {
      throw new Error("vt results not found");
    }
    const resultsTxt = resultsUrl.replace(/\.json$/, ".txt");
    setLink("#vt-results-text", resultsTxt);
    setLink("#vt-results-json", resultsUrl);
    const data = await response.json();
    const files = data.files || [];

    summary.textContent = `Report generated ${new Date(data.generated_at).toLocaleString()} for ${data.release_tag || "latest"}`;
    summary.className = "status-pill ok";

    tableBody.innerHTML = "";
    files.forEach((file) => {
      const row = document.createElement("tr");
      const link = file.item_url || (file.sha256 ? `https://www.virustotal.com/gui/file/${file.sha256}` : "");
      const stats = file.stats || {};

      row.innerHTML = `
        <td class="mono">${file.name || ""}</td>
        <td>${stats.malicious ?? 0}</td>
        <td>${stats.suspicious ?? 0}</td>
        <td>${stats.undetected ?? 0}</td>
        <td><a href="${link}" target="_blank" rel="noopener">View report</a></td>
      `;
      tableBody.appendChild(row);
    });
  } catch (err) {
    summary.textContent = "VirusTotal results not available yet.";
    summary.className = "status-pill warn";
    tableBody.innerHTML = "<tr><td colspan=\"5\" class=\"mono\">No results found.</td></tr>";
  }
};

document.addEventListener("DOMContentLoaded", () => {
  initBrandMask();
  const run = async () => {
    if (document.getElementById("release-version")) {
      await loadRelease();
    }
    if (document.getElementById("vt-table")) {
      await loadVirusTotal();
    }
  };
  run();
});
