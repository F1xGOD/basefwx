const repo = "F1xGOD/basefwx";
const releaseApi = `https://api.github.com/repos/${repo}/releases/latest`;
let latestReleaseTag = "";
let latestReleaseData = null;
const assetMap = {
  "linux-amd64": {
    bin: "basefwx-linux-amd64",
    sha256: "basefwx-linux-amd64.sha256",
    md5: "basefwx-linux-amd64.md5",
    sig: "basefwx-linux-amd64.sig"
  },
  "linux-arm64": {
    bin: "basefwx-linux-arm64",
    sha256: "basefwx-linux-arm64.sha256",
    md5: "basefwx-linux-arm64.md5",
    sig: "basefwx-linux-arm64.sig"
  },
  "windows-amd64": {
    bin: "basefwx-windows-amd64.zip",
    sha256: "basefwx-windows-amd64.zip.sha256",
    md5: "basefwx-windows-amd64.zip.md5",
    sig: "basefwx-windows-amd64.zip.sig"
  },
  "windows-x86": {
    bin: "basefwx-windows-x86.zip",
    sha256: "basefwx-windows-x86.zip.sha256",
    md5: "basefwx-windows-x86.zip.md5",
    sig: "basefwx-windows-x86.zip.sig"
  },
  "mac-amd64": {
    bin: "basefwx-mac-amd64",
    sha256: "basefwx-mac-amd64.sha256",
    md5: "basefwx-mac-amd64.md5",
    sig: "basefwx-mac-amd64.sig"
  },
  "mac-arm64": {
    bin: "basefwx-mac-arm64",
    sha256: "basefwx-mac-arm64.sha256",
    md5: "basefwx-mac-arm64.md5",
    sig: "basefwx-mac-arm64.sig"
  },
  java: {
    bin: "basefwx-java.jar",
    sha256: "basefwx-java.jar.sha256",
    md5: "basefwx-java.jar.md5",
    sig: "basefwx-java.jar.sig"
  }
};

const benchLanguages = [
  { key: "python", label: "Python" },
  { key: "pypy", label: "PyPy" },
  { key: "cpp", label: "C++" },
  { key: "java", label: "Java" }
];

const setText = (id, value) => {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = value;
  }
};

const getResultsLocalBase = () => {
  const base = document.documentElement.dataset.resultsBase;
  if (base) {
    return new URL(base, window.location.href).toString();
  }
  return new URL("results/", window.location.href).toString();
};

const THEME_KEY = "basefwx-theme";
const THEME_COLORS = { dark: "#0b090f", light: "#fbf9fd" };

const lightMedia = () => window.matchMedia("(prefers-color-scheme: light)");

// Dark is this site's default, so an unset preference resolves to dark.
const effectiveTheme = () => {
  const forced = document.documentElement.dataset.theme;
  if (forced === "dark" || forced === "light") {
    return forced;
  }
  return lightMedia().matches ? "light" : "dark";
};

const initThemeToggle = () => {
  const button = document.getElementById("theme-toggle");
  const media = lightMedia();

  const sync = () => {
    const theme = effectiveTheme();
    document.querySelectorAll('meta[name="theme-color"]').forEach((meta) => {
      meta.setAttribute("content", THEME_COLORS[theme]);
    });
    if (!button) {
      return;
    }
    const next = theme === "dark" ? "light" : "dark";
    button.hidden = false;
    button.setAttribute("aria-pressed", String(theme === "dark"));
    button.setAttribute("aria-label", `Switch to the ${next} theme`);
    button.title = `Switch to the ${next} theme`;
  };

  media.addEventListener("change", sync);

  const applyTheme = (next) => {
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch (_err) {
      // Storage is blocked, so the choice lasts for this page only.
    }
    sync();
  };

  button?.addEventListener("click", () => {
    const next = effectiveTheme() === "dark" ? "light" : "dark";
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    // Where the browser has view transitions, the whole page cross-fades
    // between palettes. Everywhere else this is the plain swap that shipped
    // before, so the toggle never depends on the API being present.
    if (reduced || typeof document.startViewTransition !== "function") {
      applyTheme(next);
      return;
    }
    document.startViewTransition(() => applyTheme(next));
  });

  sync();
};

const initSectionNav = () => {
  const nav = document.querySelector(".section-nav");
  if (!nav || !("IntersectionObserver" in window)) {
    return;
  }
  const links = Array.from(nav.querySelectorAll('a[href^="#"]'));
  const tracked = links
    .map((link) => {
      const id = link.getAttribute("href")?.slice(1);
      const section = id ? document.getElementById(id) : null;
      return section ? { link, section } : null;
    })
    .filter(Boolean);
  if (!tracked.length) {
    return;
  }

  const observer = new IntersectionObserver(
    (entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
      if (!visible.length) {
        return;
      }
      const id = visible[0].target.id;
      links.forEach((link) => {
        link.classList.toggle("active", link.getAttribute("href") === `#${id}`);
      });
    },
    { rootMargin: "-20% 0px -55% 0px", threshold: [0.1, 0.35, 0.6] }
  );

  tracked.forEach(({ section }) => observer.observe(section));
};

const initScrollReveals = () => {
  const nodes = Array.from(document.querySelectorAll("[data-reveal]"));
  if (!nodes.length) return;

  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduced || !("IntersectionObserver" in window)) {
    nodes.forEach((node) => node.classList.add("is-visible"));
    return;
  }

  document.documentElement.classList.add("motion-ready");
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add("is-visible");
      observer.unobserve(entry.target);
    });
  }, { rootMargin: "0px 0px -10%", threshold: 0.16 });

  nodes.forEach((node) => observer.observe(node));
};

const setLink = (selector, url) => {
  const el = document.querySelector(selector);
  if (!el) return;
  if (url) {
    el.href = url;
    el.setAttribute("target", "_blank");
    el.setAttribute("rel", "noopener");
    el.classList.remove("disabled");
    el.removeAttribute("aria-disabled");
    el.removeAttribute("tabindex");
  } else {
    el.removeAttribute("href");
    el.removeAttribute("target");
    el.removeAttribute("rel");
    el.classList.add("disabled");
    el.setAttribute("aria-disabled", "true");
    el.setAttribute("tabindex", "-1");
  }
};

const setAssetLinkElement = (el, url) => {
  if (!el) return;
  if (url) {
    el.href = url;
    el.setAttribute("target", "_blank");
    el.setAttribute("rel", "noopener");
    el.classList.remove("disabled");
    el.removeAttribute("aria-disabled");
    el.removeAttribute("tabindex");
  } else {
    el.removeAttribute("href");
    el.removeAttribute("target");
    el.removeAttribute("rel");
    el.classList.add("disabled");
    el.setAttribute("aria-disabled", "true");
    el.setAttribute("tabindex", "-1");
  }
};

const initDisabledLinks = () => {
  document.querySelectorAll('a[aria-disabled="true"]').forEach((el) => {
    setAssetLinkElement(el, null);
  });
};

const fetchLatestRelease = async () => {
  if (latestReleaseData) {
    return latestReleaseData;
  }
  const response = await fetch(releaseApi);
  if (!response.ok) {
    throw new Error("release fetch failed");
  }
  latestReleaseData = await response.json();
  return latestReleaseData;
};

const applyAssetLinks = (assetLookup) => {
  document.querySelectorAll("[data-asset-link]").forEach((el) => {
    const assetName = el.getAttribute("data-asset-link");
    const asset = assetName ? assetLookup.get(assetName) : null;
    setAssetLinkElement(el, asset ? asset.browser_download_url : null);
  });
};

const HASH_COLLAPSED_LEN = 32;

const setHashText = (selector, value) => {
  const el = document.querySelector(`[data-hash="${selector}"]`);
  if (!el) return;
  const text = typeof value === "string" ? value : String(value ?? "");
  const isHashLike = /^[a-f0-9]+$/i.test(text);
  const canTruncate = isHashLike && text.length > HASH_COLLAPSED_LEN;

  el.dataset.fullHash = text;
  el.classList.remove("expanded");
  el.textContent = canTruncate ? text.slice(0, HASH_COLLAPSED_LEN) : text;

  if (canTruncate) {
    el.classList.add("truncated");
    el.style.cursor = "pointer";
    el.setAttribute("role", "button");
    el.setAttribute("tabindex", "0");
    el.setAttribute("aria-expanded", "false");
    const toggle = function () {
      const expanded = this.classList.toggle("expanded");
      this.setAttribute("aria-expanded", String(expanded));
      this.textContent = expanded ? this.dataset.fullHash || "" : (this.dataset.fullHash || "").slice(0, HASH_COLLAPSED_LEN);
    };
    el.onclick = function (event) {
      event.preventDefault();
      toggle.call(this);
    };
    el.onkeydown = function (event) {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        toggle.call(this);
      }
    };
  } else {
    el.classList.remove("truncated");
    el.style.cursor = "default";
    el.onclick = null;
    el.onkeydown = null;
    el.removeAttribute("role");
    el.removeAttribute("tabindex");
    el.removeAttribute("aria-expanded");
  }
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
  if (!Number.isFinite(baseNs) || !Number.isFinite(otherNs) || baseNs <= 0 || otherNs <= 0) {
    return { label: "Not measurable (below timer resolution)", className: "delta-na" };
  }
  if (baseNs < epsilon || otherNs < epsilon) {
    return { label: "Not measurable (below timer resolution)", className: "delta-na" };
  }
  const absDiff = Math.abs(otherNs - baseNs);
  if (absDiff < epsilon) {
    return { label: "Same (±0.00%)", className: "delta-same" };
  }
  const isFaster = otherNs < baseNs;
  const pct = isFaster ? (baseNs / otherNs - 1) * 100 : (otherNs / baseNs - 1) * 100;
  const pctLabel = Math.abs(pct).toFixed(2);
  return {
    label: isFaster ? `Faster (+${pctLabel}%)` : `Slower (−${pctLabel}%)`,
    className: isFaster ? "delta-fast" : "delta-slow"
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
      <td class="bench-runtime">${lang.label}</td>
      <td class="mono">${formatNs(ns, epsilon)}</td>
      <td><span class="${delta.className}">${delta.label}</span></td>
    `;
    tableBody.appendChild(row);
  });
  if (!tableBody.children.length) {
    tableBody.innerHTML = "<tr><td colspan=\"3\" class=\"mono\">No benchmark data available.</td></tr>";
  }
};

// Loaded lazily by ensureHeavinessManifest(). Shape matches
// website/results/heaviness.json: { levels: {low,medium,high,extreme:
// {label,color,explanation}}, methods: [{match,level,notes},...] }.
let heavinessManifest = null;
let heavinessManifestPromise = null;

const ensureHeavinessManifest = async () => {
  if (heavinessManifest !== null) return heavinessManifest;
  if (heavinessManifestPromise) return heavinessManifestPromise;
  const root = document.documentElement;
  const base = root.getAttribute("data-results-base") || "results/";
  const url = `${base}heaviness.json`;
  heavinessManifestPromise = fetch(url, { cache: "no-store" })
    .then((r) => (r.ok ? r.json() : null))
    .catch(() => null)
    .then((manifest) => {
      heavinessManifest = manifest || { levels: {}, methods: [] };
      return heavinessManifest;
    });
  return heavinessManifestPromise;
};

const _matchMethodEntry = (label) => {
  if (!heavinessManifest || !label) return null;
  const lower = label.toLowerCase();
  // Match longest "match" string first so e.g. "fwxaes_live" wins
  // over "fwxaes" when both apply.
  const methods = (heavinessManifest.methods || [])
    .slice()
    .sort((a, b) => (b.match || "").length - (a.match || "").length);
  for (const m of methods) {
    if (m.match && lower.includes(m.match.toLowerCase())) return m;
  }
  return null;
};

const classifyHeaviness = (label) => {
  const m = _matchMethodEntry(label);
  if (!m) return null;
  const level = (heavinessManifest.levels || {})[m.level];
  if (!level) return null;
  return { level: m.level, ...level, notes: m.notes || "" };
};

const classifyLifecycle = (label) => {
  const m = _matchMethodEntry(label);
  if (!m) return null;
  const status = m.status || "active";
  if (status === "active") return null;
  const tier = (heavinessManifest.lifecycle || {})[status];
  if (!tier) return null;
  return {
    status,
    ...tier,
    since: m.since || "",
    notes: m.notes || ""
  };
};

const renderHeavinessChip = (label) => {
  const cls = classifyHeaviness(label);
  if (!cls) return "";
  const tooltip = escapeHtml(cls.notes || cls.explanation || "");
  const level = /^[a-z]+$/.test(cls.level) ? cls.level : "unknown";
  return `<span class="chip heaviness heaviness-${level}" title="${tooltip}" aria-label="Heaviness: ${escapeHtml(cls.label)}. ${tooltip}">${escapeHtml(cls.label)}</span>`;
};

const renderLifecycleChip = (label) => {
  const cls = classifyLifecycle(label);
  if (!cls) return "";
  const since = cls.since ? ` since ${cls.since}` : "";
  const visible = `${cls.label}${since}`;
  const tooltip = escapeHtml(cls.notes || cls.explanation || "");
  const status = /^[a-z-]+$/.test(cls.status) ? cls.status : "unknown";
  return `<span class="chip lifecycle lifecycle-${status}" title="${tooltip}" aria-label="${escapeHtml(cls.label)}${escapeHtml(since)}. ${tooltip}">${escapeHtml(visible)}</span>`;
};

const renderBenchDetails = async (container, tests, epsilon) => {
  container.innerHTML = "";
  if (!tests.length) {
    container.innerHTML = "<div class=\"card\"><p>No detailed benchmark data available.</p></div>";
    return;
  }
  // Make sure the heaviness manifest is loaded BEFORE the forEach
  // runs. Otherwise the chip helpers see `heavinessManifest === null`
  // and return empty strings, and the page renders without chips.
  // The fetch is one-shot (subsequent calls hit the cached promise),
  // so the await is free after first load.
  await ensureHeavinessManifest();
  tests.forEach((entry) => {
    const baseNs = entry.times?.python;
    const details = document.createElement("details");
    details.className = "bench-detail";
    const summary = document.createElement("summary");
    // Layout: lifecycle (deprecated/retired) prefixes the LEFT span next
    // to the label. Slate gray draws attention where the eye lands
    // first. Heaviness (low/medium/high/extreme) suffixes the RIGHT span
    // next to the timing. Its warm palette sits with the
    // operational data. This split also avoids the visual clash that
    // existed when both chips appeared adjacent with similar yellow tones.
    summary.innerHTML = `
      <span>${renderLifecycleChip(entry.label)}${escapeHtml(entry.label)}</span>
      <span class="bench-summary">${baseNs ? `Python ${formatNs(baseNs, epsilon)}` : "Python n/a"}${renderHeavinessChip(entry.label)}</span>
    `;
    details.appendChild(summary);
    const table = document.createElement("table");
    table.className = "bench-table";
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
    // The table has a min-width, so it needs its own scroll container or it
    // pushes the whole page sideways on a phone.
    const scroll = document.createElement("div");
    scroll.className = "table-scroll";
    scroll.appendChild(table);
    details.appendChild(scroll);
    container.appendChild(details);
  });
};

let pinnedResultsBasePromise = null;

const getPinnedResultsBase = async () => {
  if (!pinnedResultsBasePromise) {
    pinnedResultsBasePromise = fetch(`https://api.github.com/repos/${repo}/commits/DEV`, {
      headers: { Accept: "application/vnd.github+json" },
      cache: "no-store"
    })
      .then((response) => {
        if (!response.ok) throw new Error("results revision fetch failed");
        return response.json();
      })
      .then((data) => {
        const revision = String(data.sha || "");
        if (!/^[a-f0-9]{40}$/i.test(revision)) {
          throw new Error("invalid results revision");
        }
        return `https://raw.githubusercontent.com/${repo}/${revision}/website/results`;
      })
      .catch(() => "");
  }
  return pinnedResultsBasePromise;
};

const loadRelease = async () => {
  try {
    const data = await fetchLatestRelease();
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

    Object.entries(assetMap).forEach(([key, values]) => {
      const binAsset = assetLookup.get(values.bin);
      const sigAsset = assetLookup.get(values.sig);
      setLink(`[data-download="${key}"]`, binAsset ? binAsset.browser_download_url : null);
      setLink(`[data-asset="${key}.sig"]`, sigAsset ? sigAsset.browser_download_url : null);
      setHashText(`${key}.sha256`, "Loading…");
      setHashText(`${key}.md5`, "Loading…");
    });
    applyAssetLinks(assetLookup);
  } catch (err) {
    setText("release-version", "Release data unavailable");
    setText("release-date", "Check GitHub for details");
    setText("release-assets", "");
    Object.entries(assetMap).forEach(([key]) => {
      setLink(`[data-download="${key}"]`, null);
      setLink(`[data-asset="${key}.sig"]`, null);
    });
    applyAssetLinks(new Map());
  }
};

const parseHashFile = (assetName, body) => {
  const expectedLength = assetName.endsWith(".md5") ? 32 : 64;
  const matcher = new RegExp(`\\b[a-fA-F0-9]{${expectedLength}}\\b`);
  const match = String(body || "").match(matcher);
  if (match) {
    return match[0].toLowerCase();
  }
  const first = String(body || "").trim().split(/\s+/)[0] || "";
  return first || "Unavailable";
};

const loadHashFiles = async () => {
  const nodes = Array.from(document.querySelectorAll("[data-hash-file]"));
  if (!nodes.length) {
    return;
  }
  try {
    const data = await fetchLatestRelease();
    latestReleaseTag = data.tag_name || latestReleaseTag;
    const assets = data.assets || [];
    const assetLookup = new Map(assets.map((asset) => [asset.name, asset]));
    applyAssetLinks(assetLookup);
    const localBase = getResultsLocalBase();

    await Promise.all(
      nodes.map(async (node) => {
        const assetName = node.getAttribute("data-hash-file");
        if (!assetName) {
          node.textContent = "Unavailable";
          return;
        }
        const asset = assetLookup.get(assetName);
        if (!asset) {
          node.textContent = "Missing release asset";
          return;
        }
        const candidates = [asset.browser_download_url, `${localBase}${assetName}`];
        try {
          let response = null;
          for (const candidate of candidates) {
            const attempt = await fetch(candidate);
            if (attempt.ok) {
              response = attempt;
              break;
            }
          }
          if (!response) {
            throw new Error("hash fetch failed");
          }
          const body = await response.text();
          node.textContent = parseHashFile(assetName, body);
        } catch (_err) {
          node.textContent = "Unavailable";
        }
      })
    );
  } catch (_err) {
    nodes.forEach((node) => {
      node.textContent = "Unavailable";
    });
  }
};

const loadVirusTotal = async () => {
  const summary = document.getElementById("vt-summary");
  const tableBody = document.querySelector("#vt-table tbody");
  const releaseAssets = Array.isArray(latestReleaseData?.assets) ? latestReleaseData.assets : [];
  const releaseReport = releaseAssets.find((asset) => asset.name === "virustotal-results.json");
  const releaseReportText = releaseAssets.find((asset) => asset.name === "virustotal-results.txt");
  if (releaseReport?.browser_download_url) {
    setLink("#vt-results-json", releaseReport.browser_download_url);
  }
  if (releaseReportText?.browser_download_url) {
    setLink("#vt-results-text", releaseReportText.browser_download_url);
  }

  try {
    const pinnedBase = await getPinnedResultsBase();
    const localBase = getResultsLocalBase();
    const candidates = [
      pinnedBase ? `${pinnedBase}/virustotal-latest.json` : "",
      `${localBase}virustotal-latest.json`
    ].filter(Boolean);

    let resultsUrl = "";
    let response = null;
    for (const candidate of candidates) {
      try {
        const attempt = await fetch(candidate);
        if (attempt.ok) {
          resultsUrl = candidate;
          response = attempt;
          break;
        }
      } catch (_err) {
        // One unavailable mirror must not suppress the remaining trusted copies.
      }
    }
    if (!response) {
      throw new Error("vt results not found");
    }
    const data = await response.json();
    const files = data.files || [];

    if (latestReleaseTag && data.release_tag && data.release_tag !== latestReleaseTag) {
      throw new Error("VirusTotal report does not match the latest release");
    }

    setLink("#vt-results-text", resultsUrl.replace(/\.json$/, ".txt"));
    setLink("#vt-results-json", resultsUrl);

    summary.textContent = `Links generated ${new Date(data.generated_at).toLocaleString()} for ${data.release_tag || "latest"}. Review each report on VirusTotal.`;
    summary.className = "status-pill ok";

    tableBody.innerHTML = "";
    const reportLink = (file) => {
      let candidate = "";
      if (file.gui_url) {
        candidate = file.gui_url;
      } else if (/^[a-f0-9]{64}$/i.test(file.scanned_sha256 || file.sha256 || "")) {
        candidate = `https://www.virustotal.com/gui/file/${file.scanned_sha256 || file.sha256}`;
      } else if (file.item_url) {
        const match = file.item_url.match(/\/files\/([^/?]+)/);
        if (match) {
          candidate = `https://www.virustotal.com/gui/file/${encodeURIComponent(match[1])}`;
        }
      }
      try {
        const url = new URL(candidate);
        const allowedHosts = new Set(["www.virustotal.com", "virustotal.com"]);
        return url.protocol === "https:" && allowedHosts.has(url.hostname) ? url.href : "";
      } catch (_err) {
        return "";
      }
    };

    files.forEach((file) => {
      const row = document.createElement("tr");
      const link = reportLink(file);
      const label = escapeHtml(file.name || "");
      const pending = file.status && file.status !== "submitted" && file.status !== "completed";
      row.innerHTML = `
        <td class="mono">${label}</td>
        <td>${
          link
            ? `<a class="vt-btn" href="${escapeHtml(link)}" target="_blank" rel="noopener">View on VirusTotal</a>`
            : `<span class="mono">${pending ? "Pending" : "Unavailable"}</span>`
        }</td>
      `;
      tableBody.appendChild(row);
    });
  } catch (err) {
    summary.textContent = releaseReport
      ? "Report files are available. Row preview awaits matching published metadata."
      : "VirusTotal links not available yet.";
    summary.className = "status-pill warn";
    tableBody.innerHTML = releaseReport
      ? "<tr><td colspan=\"2\" class=\"mono\">Open the report files above.</td></tr>"
      : "<tr><td colspan=\"2\" class=\"mono\">No results found.</td></tr>";
  }
};

const renderJavaBackendsPanel = (data) => {
  const status = document.getElementById("java-backends-status");
  const table = document.getElementById("java-backends-table");
  if (!status || !table) return;
  const tbody = table.querySelector("tbody");
  if (!data || !Array.isArray(data.samples) || data.samples.length === 0) {
    status.textContent = "No Java-backend data in this snapshot.";
    status.className = "status-pill warn";
    table.hidden = true;
    if (tbody) tbody.innerHTML = "";
    return;
  }
  // deltaInfo() takes nanoseconds and returns the same faster/slower rendering
  // used by the main benchmark table. Convert the
  // pure_java vs jni ms values to ns so we can reuse it and the JNI panel
  // matches the rest of the page (no more bespoke "1.61× pure-java"
  // multiplier strings and no more rowspan-breaks-card-layout).
  const MS_TO_NS = 1_000_000;
  const TIMER_EPSILON_NS = 200_000;  // matches the main table's threshold
  const fmtTime = (ms, mibs) => {
    if (typeof ms !== "number" || !Number.isFinite(ms)) return "Not available";
    const mibsTxt = (typeof mibs === "number") ? ` (${mibs.toFixed(0)} MiB/s)` : "";
    return `${ms.toFixed(2)} ms${mibsTxt}`;
  };
  const rows = [];
  for (const sample of data.samples) {
    const size = sample.size_human || `${sample.size_bytes} B`;
    const pure = sample.pure_java || {};
    const jni = sample.jni || {};
    const jniAvail = jni && jni.available !== false && typeof jni.encrypt_ms === "number";

    // pure-java row: its own card, "baseline" in the delta column.
    rows.push(
      `<tr>` +
      `<td><strong>${escapeHtml(size)}</strong></td>` +
      `<td>pure-java</td>` +
      `<td>${fmtTime(pure.encrypt_ms, pure.encrypt_mibs)}</td>` +
      `<td>${fmtTime(pure.decrypt_ms, pure.decrypt_mibs)}</td>` +
      `<td class="delta-base">Baseline</td>` +
      `</tr>`
    );

    // jni row: own card. Speedup column shows encrypt + decrypt deltas
    // computed by the shared deltaInfo() so the format and emoji set
    // match the main bench table.
    if (jniAvail) {
      const encDelta = deltaInfo(
        pure.encrypt_ms * MS_TO_NS,
        jni.encrypt_ms * MS_TO_NS,
        TIMER_EPSILON_NS
      );
      const decDelta = (typeof pure.decrypt_ms === "number" && typeof jni.decrypt_ms === "number")
        ? deltaInfo(pure.decrypt_ms * MS_TO_NS, jni.decrypt_ms * MS_TO_NS, TIMER_EPSILON_NS)
        : { label: "Not available", className: "delta-na" };
      // Pick the cell color from whichever direction is bigger in magnitude,
      // so a "mixed" outcome doesn't silently look like an unambiguous win.
      const rowCls = (encDelta.className === "delta-fast" && decDelta.className === "delta-fast")
        ? "delta-fast"
        : (encDelta.className === "delta-slow" && decDelta.className === "delta-slow")
          ? "delta-slow"
          : (encDelta.className === decDelta.className)
            ? encDelta.className
            : "delta-same";
      rows.push(
        `<tr>` +
        `<td><strong>${escapeHtml(size)}</strong></td>` +
        `<td>jni</td>` +
        `<td>${fmtTime(jni.encrypt_ms, jni.encrypt_mibs)}</td>` +
        `<td>${fmtTime(jni.decrypt_ms, jni.decrypt_mibs)}</td>` +
        `<td class="${rowCls}">` +
          `<div class="java-backend-delta-line">enc ${encDelta.label}</div>` +
          `<div class="java-backend-delta-line">dec ${decDelta.label}</div>` +
        `</td>` +
        `</tr>`
      );
    } else {
      rows.push(
        `<tr>` +
        `<td><strong>${escapeHtml(size)}</strong></td>` +
        `<td>jni</td>` +
        `<td colspan="3" class="mono delta-na">native library not loaded for this run</td>` +
        `</tr>`
      );
    }
  }
  if (tbody) tbody.innerHTML = rows.join("");
  table.hidden = false;
  status.textContent = `${data.samples.length} payload size(s)`;
  status.className = "status-pill ok";
};

const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));

let benchHistorySnapshots = [];
let benchHistoryLatestTag = "";

const populateBenchHistory = async () => {
  const select = document.getElementById("bench-history");
  if (!select) return;
  try {
    const base = await getPinnedResultsBase();
    if (!base) throw new Error("no pinned results revision");
    const res = await fetch(`${base}/index.json`);
    if (!res.ok) throw new Error("no history index");
    const idx = await res.json();
    benchHistorySnapshots = Array.isArray(idx.snapshots) ? idx.snapshots : [];
    benchHistoryLatestTag = idx.latest || "";
    const opts = [`<option value="">latest</option>`];
    for (const snap of benchHistorySnapshots) {
      opts.push(`<option value="${escapeHtml(snap.tag)}">${escapeHtml(snap.tag)}</option>`);
    }
    select.innerHTML = opts.join("");
    select.disabled = benchHistorySnapshots.length === 0;
    select.addEventListener("change", () => loadBenchmarks(select.value || ""));
  } catch (err) {
    select.innerHTML = `<option value="">latest</option>`;
    select.disabled = true;
  }
};

const loadJavaBackendsForTag = async (tag) => {
  const base = await getPinnedResultsBase();
  const local = getResultsLocalBase();
  const filenames = tag
    ? [`java-backends-${tag}.json`]
    : [`java-backends-latest.json`];
  for (const fn of filenames) {
    for (const url of [base ? `${base}/${fn}` : "", `${local}${fn}`].filter(Boolean)) {
      try {
        const res = await fetch(url);
        if (res.ok) {
          renderJavaBackendsPanel(await res.json());
          return;
        }
      } catch (_) { /* try next */ }
    }
  }
  renderJavaBackendsPanel(null);
};

const loadBenchmarks = async (explicitTag = "") => {
  const status = document.getElementById("bench-status");
  const tableBody = document.querySelector("#bench-overall-table tbody");
  const detailsContainer = document.getElementById("bench-details");
  if (!status || !tableBody || !detailsContainer) {
    return;
  }
  try {
    const pinnedBase = await getPinnedResultsBase();
    const localBase = getResultsLocalBase();
    const candidates = explicitTag
      ? [
          pinnedBase ? `${pinnedBase}/benchmarks-${explicitTag}.json` : "",
          `${localBase}benchmarks-${explicitTag}.json`
        ].filter(Boolean)
      : [
          pinnedBase && latestReleaseTag ? `${pinnedBase}/benchmarks-${latestReleaseTag}.json` : "",
          pinnedBase ? `${pinnedBase}/benchmarks-latest.json` : "",
          latestReleaseTag ? `${localBase}benchmarks-${latestReleaseTag}.json` : "",
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
    const expectedTag = explicitTag || latestReleaseTag;
    if (expectedTag && data.release_tag && data.release_tag !== expectedTag) {
      throw new Error("benchmark report does not match the selected release");
    }
    const epsilon = Number(data.epsilon_ns) || 1_000_000;
    const generatedAt = data.generated_at
      ? new Date(data.generated_at).toLocaleString()
      : "Unknown";
    setText("bench-release", data.release_tag || (explicitTag ? explicitTag : "Latest benchmark"));
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
    await renderBenchDetails(detailsContainer, tests, epsilon);

    await loadJavaBackendsForTag(explicitTag || data.release_tag || "");
  } catch (err) {
    status.textContent = "Benchmark results not available yet.";
    status.className = "status-pill warn";
    tableBody.innerHTML = "<tr><td colspan=\"3\" class=\"mono\">No results found.</td></tr>";
    detailsContainer.innerHTML = "<div class=\"card\">No detailed benchmark data available.</div>";
    renderJavaBackendsPanel(null);
  }
};

const initDocToc = () => {
  const article = document.querySelector(".doc-article");
  const toc = document.getElementById("doc-toc-list");
  if (!article || !toc) return;

  const details = toc.closest(".doc-toc");
  if (window.matchMedia("(max-width: 940px)").matches) {
    details?.removeAttribute("open");
  }

  const headings = Array.from(article.querySelectorAll("h2, h3"));
  if (!headings.length) {
    details?.setAttribute("hidden", "");
    return;
  }

  const usedIds = new Set(Array.from(document.querySelectorAll("[id]"), (el) => el.id));
  headings.forEach((heading, index) => {
    if (!heading.id) {
      const base = heading.textContent
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-|-$/g, "") || `section-${index + 1}`;
      let id = base;
      let suffix = 2;
      while (usedIds.has(id)) id = `${base}-${suffix++}`;
      heading.id = id;
      usedIds.add(id);
    }
    const link = document.createElement("a");
    link.href = `#${heading.id}`;
    link.dataset.level = heading.tagName.slice(1);
    link.textContent = heading.textContent;
    toc.appendChild(link);
  });
};

document.addEventListener("DOMContentLoaded", () => {
  initThemeToggle();
  initDisabledLinks();
  initSectionNav();
  initScrollReveals();
  initDocToc();
  const run = async () => {
    if (document.getElementById("release-version") || document.getElementById("bench-release")) {
      await loadRelease();
    }
    if (document.querySelector("[data-hash-file]")) {
      await loadHashFiles();
    }
    if (document.getElementById("vt-table")) {
      await loadVirusTotal();
    }
    if (document.getElementById("bench-overall-table")) {
      await populateBenchHistory();
      await loadBenchmarks();
    }
  };
  run();
});
