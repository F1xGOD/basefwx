const repo = "F1xGOD/basefwx";
const releaseApi = `https://api.github.com/repos/${repo}/releases/latest`;
let latestReleaseTag = "";
const vtHashes = new Map();
const vtFlags = new Map();
const VT_OK_ICON = `
  <svg class="vt-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" aria-hidden="true">
    <path d="M382-240 154-468l57-57 171 171 367-367 57 57-424 424Z" />
  </svg>
`;
const VT_WARN_ICON = `
  <svg class="vt-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" aria-hidden="true">
    <path d="m40-120 440-760 440 760H40Zm138-80h604L480-720 178-200Zm302-40q17 0 28.5-11.5T520-280q0-17-11.5-28.5T480-320q-17 0-28.5 11.5T440-280q0 17 11.5 28.5T480-240Zm-40-120h80v-200h-80v200Zm40-100Z" />
  </svg>
`;
const VT_BAD_ICON = `
  <svg class="vt-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" aria-hidden="true">
    <path d="M330-120 120-330v-300l210-210h300l210 210v300L630-120H330Zm36-190 114-114 114 114 56-56-114-114 114-114-56-56-114 114-114-114-56 56 114 114-114 114 56 56Zm-2 110h232l164-164v-232L596-760H364L200-596v232l164 164Zm116-280Z" />
  </svg>
`;
const VT_HASH_ICON = `
  <svg class="vt-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" aria-hidden="true">
    <path d="m840-234-80-80v-446q0-17 11.5-28.5T800-800q17 0 28.5 11.5T840-760v526ZM360-714l-80-80v-6q0-17 11.5-28.5T320-840q17 0 28.5 11.5T360-800v86Zm160 160-80-80v-246q0-17 11.5-28.5T480-920q17 0 28.5 11.5T520-880v326Zm160 81h-80v-367q0-17 11.5-28.5T640-880q17 0 28.5 11.5T680-840v367Zm37 343L360-487v224L212-367l157 229q5 8 14 13t19 5h278q10 0 19.5-2.5T717-130ZM402-40q-30 0-56-13.5T303-92L48-465l24-23q19-19 45-22t47 12l116 81v-150L27-820l57-57L876-85l-57 57-44-44q-20 15-44 23.5T680-40H402Zm137-268Zm61-165Z" />
  </svg>
`;
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

const benchLanguages = [
  { key: "python", label: "Python", emoji: "🐍" },
  { key: "pypy", label: "PyPy", emoji: "🥭" },
  { key: "cpp", label: "C++", emoji: "⚙️" },
  { key: "java", label: "Java", emoji: "☕" }
];

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

const setHashText = (selector, value) => {
  const el = document.querySelector(`[data-hash="${selector}"]`);
  if (!el) return;
  el.textContent = value;
};

const applyVtHashes = () => {
  Object.entries(assetMap).forEach(([key, values]) => {
    const match = vtHashes.get(values.bin);
    setHashText(`${key}.sha256`, match?.sha256 || "Hash not available");
    setHashText(`${key}.md5`, match?.md5 || "Hash not available");
  });
};

const applyDownloadFlags = () => {
  Object.entries(assetMap).forEach(([key, values]) => {
    const flags = vtFlags.get(values.bin);
    if (flags?.hashIssue) {
      const download = document.querySelector(`[data-download="${key}"]`);
      const sig = document.querySelector(`[data-asset="${key}.sig"]`);
      if (download) {
        download.href = "#";
        download.classList.add("disabled");
        download.setAttribute("title", "Download disabled due to hash mismatch");
      }
      if (sig) {
        sig.href = "#";
        sig.classList.add("disabled");
        sig.setAttribute("title", "Signature disabled due to hash mismatch");
      }
    }
  });
};

const formatNs = (ns, epsilon) => {
  if (!Number.isFinite(ns)) {
    return "n/a";
  }
  if (ns < epsilon) {
    return "≈0s (below resolution)";
  }
  return `${(ns / 1_000_000_000).toFixed(3)}s`;
};

const deltaInfo = (baseNs, otherNs, epsilon) => {
  if (!Number.isFinite(baseNs) || !Number.isFinite(otherNs)) {
    return { label: "n/a", className: "delta-na" };
  }
  if (baseNs < epsilon || otherNs < epsilon) {
    return { label: "❓ Not measurable", className: "delta-na" };
  }
  const pct = ((baseNs - otherNs) / baseNs) * 100;
  const absPct = Math.abs(pct);
  if (absPct < 0.005) {
    return { label: "🔵 Same (±0.00%)", className: "delta-same" };
  }
  if (absPct >= 100) {
    const ratio = pct > 0 ? baseNs / otherNs : otherNs / baseNs;
    const ratioLabel = Number.isFinite(ratio) ? ratio.toFixed(2) : "∞";
    return {
      label: pct > 0 ? `⚡ Faster (${ratioLabel}×)` : `🐌 Slower (${ratioLabel}×)`,
      className: pct > 0 ? "delta-fast" : "delta-slow"
    };
  }
  const pctLabel = absPct.toFixed(2);
  return {
    label: pct > 0 ? `⚡ Faster (+${pctLabel}%)` : `🐌 Slower (−${pctLabel}%)`,
    className: pct > 0 ? "delta-fast" : "delta-slow"
  };
};

const computeOverall = (tests) => {
  const totals = {};
  benchLanguages.forEach((lang) => {
    totals[lang.key] = { time_ns: 0, baseline_ns: 0, count: 0 };
  });
  tests.forEach((entry) => {
    const base = entry.times?.python;
    if (!Number.isFinite(base)) {
      return;
    }
    benchLanguages.forEach((lang) => {
      const value = entry.times?.[lang.key];
      if (!Number.isFinite(value)) {
        return;
      }
      totals[lang.key].time_ns += value;
      totals[lang.key].baseline_ns += base;
      totals[lang.key].count += 1;
    });
  });
  const result = {};
  benchLanguages.forEach((lang) => {
    const entry = totals[lang.key];
    if (entry.count > 0 && entry.time_ns > 0) {
      result[lang.key] = entry;
    }
  });
  return result;
};

const renderBenchTable = (tableBody, timesByLang, epsilon) => {
  tableBody.innerHTML = "";
  const baseNs = timesByLang?.python?.time_ns ?? timesByLang?.python;
  benchLanguages.forEach((lang) => {
    const value = timesByLang?.[lang.key];
    const ns = value && typeof value === "object" ? value.time_ns : value;
    if (!Number.isFinite(ns)) {
      return;
    }
    const delta = lang.key === "python"
      ? { label: "Baseline", className: "delta-base" }
      : deltaInfo(baseNs, ns, epsilon);
    const row = document.createElement("tr");
    row.innerHTML = `
      <td class="bench-runtime">${lang.emoji} ${lang.label}</td>
      <td class="mono">${formatNs(ns, epsilon)}</td>
      <td><span class="${delta.className}">${delta.label}</span></td>
    `;
    tableBody.appendChild(row);
  });
  if (!tableBody.children.length) {
    tableBody.innerHTML = "<tr><td colspan=\"3\" class=\"mono\">No benchmark data available.</td></tr>";
  }
};

const renderBenchDetails = (container, tests, epsilon) => {
  container.innerHTML = "";
  if (!tests.length) {
    container.innerHTML = "<div class=\"card\">No detailed benchmark data available.</div>";
    return;
  }
  tests.forEach((entry) => {
    const baseNs = entry.times?.python;
    const details = document.createElement("details");
    details.className = "bench-detail";
    const summary = document.createElement("summary");
    summary.innerHTML = `
      <span>${entry.label}</span>
      <span class="bench-summary">${baseNs ? `Python ${formatNs(baseNs, epsilon)}` : "Python n/a"}</span>
    `;
    details.appendChild(summary);
    const table = document.createElement("table");
    table.className = "bench-table bench-table-compact";
    table.innerHTML = `
      <thead>
        <tr>
          <th>Runtime</th>
          <th>Time</th>
          <th>Delta vs Python</th>
        </tr>
      </thead>
      <tbody></tbody>
    `;
    renderBenchTable(table.querySelector("tbody"), entry.times || {}, epsilon);
    details.appendChild(table);
    container.appendChild(details);
  });
};

const getResultsBases = (tag) => {
  const mainBase = `https://raw.githubusercontent.com/${repo}/refs/heads/main/results`;
  const tagBase = tag ? `https://raw.githubusercontent.com/${repo}/refs/heads/results/${tag}/results` : "";
  return {
    primary: mainBase,
    fallback: tagBase || mainBase
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
      setHashText(`${key}.sha256`, "Awaiting VirusTotal");
      setHashText(`${key}.md5`, "Awaiting VirusTotal");
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
    vtHashes.clear();
    vtFlags.clear();
    const toGuiLink = (file) => {
      if (file.sha256) {
        return `https://www.virustotal.com/gui/file/${file.sha256}`;
      }
      if (file.item_url) {
        const match = file.item_url.match(/\/files\/([^/?]+)/);
        if (match) {
          return `https://www.virustotal.com/gui/file/${match[1]}`;
        }
      }
      return "";
    };

    files.forEach((file) => {
      const row = document.createElement("tr");
      const link = toGuiLink(file);
      const stats = file.stats || {};
      const malicious = Number(stats.malicious ?? 0);
      const suspicious = Number(stats.suspicious ?? 0);
      const undetected = Number(stats.undetected ?? 0);
      const ok = undetected > 61 && suspicious < 3 && malicious <= 1;
      const validSha256 = typeof file.sha256 === "string" && /^[a-f0-9]{64}$/i.test(file.sha256);
      const validMd5 = typeof file.md5 === "string" && /^[a-f0-9]{32}$/i.test(file.md5);
      const hashIssue = !validSha256 || !validMd5;
      let statusIcon = VT_WARN_ICON;
      let statusClass = "vt-check warn";
      let statusLabel = "VirusTotal caution";
      if (hashIssue) {
        statusIcon = VT_HASH_ICON;
        statusClass = "vt-check hash";
        statusLabel = "Hash or signature metadata issue";
      } else if (malicious > 4 || suspicious > 12) {
        statusIcon = VT_BAD_ICON;
        statusClass = "vt-check bad";
        statusLabel = "VirusTotal high risk";
      } else if (ok) {
        statusIcon = VT_OK_ICON;
        statusClass = "vt-check ok";
        statusLabel = "VirusTotal pass";
      }

      vtHashes.set(file.name || "", {
        sha256: file.sha256 || "",
        md5: file.md5 || ""
      });
      vtFlags.set(file.name || "", { hashIssue });

      row.innerHTML = `
        <td class="mono">
          <div class="vt-file-cell">
            <span class="${statusClass}" aria-label="${statusLabel}" title="${statusLabel}">${statusIcon}</span>
            ${file.name || ""}
          </div>
        </td>
        <td>${malicious}</td>
        <td>${suspicious}</td>
        <td>${undetected}</td>
        <td><a class="vt-btn" href="${link}" target="_blank" rel="noopener">View report</a></td>
      `;
      tableBody.appendChild(row);
    });
    applyVtHashes();
    applyDownloadFlags();
  } catch (err) {
    summary.textContent = "VirusTotal results not available yet.";
    summary.className = "status-pill warn";
    tableBody.innerHTML = "<tr><td colspan=\"5\" class=\"mono\">No results found.</td></tr>";
  }
};

const loadBenchmarks = async () => {
  const status = document.getElementById("bench-status");
  const tableBody = document.querySelector("#bench-overall-table tbody");
  const detailsContainer = document.getElementById("bench-details");
  if (!status || !tableBody || !detailsContainer) {
    return;
  }
  try {
    const resultsBases = getResultsBases(latestReleaseTag);
    const localBase = new URL("results/", window.location.href).toString();
    const candidates = [
      `${resultsBases.primary}/benchmarks-latest.json`,
      latestReleaseTag ? `${resultsBases.primary}/benchmarks-${latestReleaseTag}.json` : "",
      `${resultsBases.fallback}/benchmarks-latest.json`,
      latestReleaseTag ? `${resultsBases.fallback}/benchmarks-${latestReleaseTag}.json` : "",
      `${localBase}benchmarks-latest.json`
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
      throw new Error("bench results not found");
    }
    const resultsTxt = resultsUrl.replace(/\.json$/, ".txt");
    setLink("#bench-results-text", resultsTxt);
    setLink("#bench-results-json", resultsUrl);
    const data = await response.json();
    const epsilon = Number(data.epsilon_ns) || 1_000_000;
    const generatedAt = data.generated_at
      ? new Date(data.generated_at).toLocaleString()
      : "Unknown";
    setText("bench-release", data.release_tag || "Latest benchmark");
    setText("bench-date", generatedAt);
    setText(
      "bench-meta",
      `iters: ${data.bench_iters || "--"} · warmup: ${data.bench_warmup || "--"} · workers: ${data.bench_workers || "--"}`
    );

    const tests = Array.isArray(data.tests) ? data.tests : [];
    const overall = data.overall && Object.keys(data.overall).length
      ? data.overall
      : computeOverall(tests);

    status.textContent = `Report generated ${generatedAt}`;
    status.className = "status-pill ok";
    renderBenchTable(tableBody, overall, epsilon);
    renderBenchDetails(detailsContainer, tests, epsilon);
  } catch (err) {
    status.textContent = "Benchmark results not available yet.";
    status.className = "status-pill warn";
    tableBody.innerHTML = "<tr><td colspan=\"3\" class=\"mono\">No results found.</td></tr>";
    detailsContainer.innerHTML = "<div class=\"card\">No detailed benchmark data available.</div>";
  }
};

document.addEventListener("DOMContentLoaded", () => {
  initBrandMask();
  const run = async () => {
    if (document.getElementById("release-version") || document.getElementById("bench-release")) {
      await loadRelease();
    }
    if (document.getElementById("vt-table")) {
      await loadVirusTotal();
    }
    if (document.getElementById("bench-overall-table")) {
      await loadBenchmarks();
    }
  };
  run();
});
