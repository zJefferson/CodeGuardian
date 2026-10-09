"use strict";

/*
 * Interface do CodeGuardian.
 *
 * Consome apenas os endpoints da API. Todo conteúdo do relatório pode vir de
 * repositórios não confiáveis, por isso é inserido somente como texto
 * (textContent / nós de texto) e links só são criados para URLs https://.
 */

const POLL_INTERVAL_MS = 1500;
const MAX_POLL_DURATION_MS = 20 * 60 * 1000;
const FINDINGS_PAGE_SIZE = 100;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const JOB_STATUS = {
  queued: { label: "Na fila", tone: "info" },
  running: { label: "Em execução", tone: "info" },
  completed: { label: "Concluída", tone: "success" },
  failed: { label: "Falhou", tone: "danger" },
};

const OVERALL_STATUS = {
  no_issues_found: {
    label: "Sem achados",
    tone: "success",
    lead: "Todas as verificações aplicáveis foram concluídas sem achados.",
  },
  issues_found: {
    label: "Achados encontrados",
    tone: "warning",
    lead: "As verificações foram concluídas e encontraram problemas (detalhes abaixo).",
  },
  nothing_to_analyze: {
    label: "Nada a analisar",
    tone: "neutral",
    lead: "Não há código Python nem dependências para avaliar neste repositório.",
  },
  incomplete: {
    label: "Análise incompleta",
    tone: "warning",
    lead: "Algumas verificações não foram concluídas; o resultado não é conclusivo e não foi aprovado.",
  },
  failed: {
    label: "Análise falhou",
    tone: "danger",
    lead: "A análise não pôde ser realizada (veja os erros abaixo).",
  },
};

const CHECK_STATUS = {
  completed: { label: "Concluída", tone: "success" },
  partial: { label: "Parcial", tone: "warning" },
  failed: { label: "Falhou", tone: "danger" },
  skipped: { label: "Não executada", tone: "neutral" },
  not_applicable: { label: "Não aplicável", tone: "neutral" },
};

const CHECK_NAMES = {
  repository: "Repositório (validação e clonagem)",
  structure: "Estrutura do projeto",
  ruff: "Análise estática (Ruff)",
  dependencies: "Dependências (pip-audit)",
  tests: "Testes (pytest isolado)",
};

const SCORE_STATUS = {
  available: { label: "Disponível", tone: "success" },
  unavailable: { label: "Indisponível", tone: "neutral" },
  not_applicable: { label: "Não aplicável", tone: "neutral" },
};

const DIMENSION_NAMES = {
  static_analysis: "Análise estática",
  dependencies: "Dependências",
  practices: "Práticas do projeto",
  tests: "Testes executados",
};

const AUDIT_STATUS = {
  no_vulnerabilities: "Nenhuma vulnerabilidade conhecida nas versões auditadas",
  vulnerabilities_found: "Vulnerabilidades encontradas",
  no_dependency_files: "Nenhum arquivo de dependências encontrado",
  no_auditable_dependencies: "Nenhuma dependência com versão exata para auditar",
  source_unavailable: "Fonte de vulnerabilidades indisponível",
  timeout: "Tempo limite excedido",
  output_limit: "Limite de saída excedido",
  failed: "Falha na execução do pip-audit",
};

const RUFF_STATUS = {
  completed: "Concluída",
  no_python_files: "Nenhum arquivo Python",
  timeout: "Tempo limite excedido",
  output_limit: "Limite de saída excedido",
  failed: "Falha na execução do Ruff",
};

const TEST_STATUS = {
  disabled: "Desabilitada",
  skipped_unavailable: "Ignorada: ambiente isolado indisponível",
  no_tests: "Nenhum teste encontrado",
  passed: "Todos os testes passaram",
  failed: "Testes reprovados",
  collection_error: "Erro ao coletar os testes",
  pytest_error: "Erro do pytest",
  timeout: "Tempo limite excedido",
  resource_limit: "Limite de recursos excedido",
  infrastructure_error: "Falha de infraestrutura",
};

/* --- Utilitários de DOM (somente texto) ------------------------------------ */

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = String(value);
    else if (key === "dataset") Object.assign(node.dataset, value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  append(node, children);
  return node;
}

function append(node, children) {
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function badge(text, tone) {
  return el("span", { class: `badge ${tone || "neutral"}`, text });
}

function safeLink(url, text) {
  if (typeof url === "string" && url.startsWith("https://")) {
    return el("a", { href: url, target: "_blank", rel: "noopener noreferrer", text: text || url });
  }
  return el("span", { text: text || "" });
}

function section(title, ...children) {
  return el("section", { class: "card" }, el("h2", { text: title }), ...children);
}

function definitionList(entries) {
  const list = el("dl", { class: "details" });
  for (const [term, value] of entries) {
    if (value === undefined || value === null || value === "") continue;
    append(list, [el("dt", { text: term }), el("dd", {}, value)]);
  }
  return list;
}

function table(headers, rows, caption) {
  const head = el("thead", {}, el("tr", {}, headers.map((h) => el("th", { scope: "col", text: h }))));
  const body = el("tbody", {}, rows.map((cells) => el("tr", {}, cells.map((c) => el("td", {}, c)))));
  return el(
    "div",
    { class: "table-wrap" },
    el("table", {}, caption ? el("caption", { class: "visually-hidden", text: caption }) : null, head, body),
  );
}

function notice(text, tone = "info") {
  return el("p", { class: `message ${tone}`, text });
}

function formatNumber(value, digits = 0) {
  if (value === null || value === undefined) return "—";
  return Number(value).toLocaleString("pt-BR", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString("pt-BR");
}

function show(node, visible = true) {
  node.hidden = !visible;
}

/* --- Cliente da API ---------------------------------------------------------- */

class ApiError extends Error {
  constructor(message, { status = 0, code = "network_error", details = [] } = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(path, {
      ...options,
      headers: { Accept: "application/json", ...(options.headers || {}) },
    });
  } catch {
    throw new ApiError("Não foi possível conectar à API. Verifique se o servidor está em execução.");
  }
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (!response.ok) {
    const error = body && body.error ? body.error : {};
    let message = error.message || `A API respondeu com o código ${response.status}.`;
    const retryAfter = response.headers.get("Retry-After");
    if (response.status === 503 && retryAfter) message += ` Tente novamente em ${retryAfter} segundos.`;
    throw new ApiError(message, {
      status: response.status,
      code: error.code || "http_error",
      details: Array.isArray(error.details) ? error.details : [],
    });
  }
  return body;
}

const api = {
  start: (repositoryUrl) =>
    request("/analyses", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repository_url: repositoryUrl }),
    }),
  status: (id) => request(`/analyses/${encodeURIComponent(id)}`),
  report: (id) => request(`/analyses/${encodeURIComponent(id)}/report`),
};

/* --- Estado da página -------------------------------------------------------- */

const ui = {};
let pollToken = 0;

function init() {
  ui.form = document.getElementById("analysis-form");
  ui.input = document.getElementById("repository-url");
  ui.submit = document.getElementById("submit-button");
  ui.formError = document.getElementById("form-error");
  ui.statusCard = document.getElementById("status-card");
  ui.statusBadge = document.getElementById("status-badge");
  ui.statusMessage = document.getElementById("status-message");
  ui.statusDetails = document.getElementById("status-details");
  ui.steps = document.getElementById("status-steps");
  ui.results = document.getElementById("results");

  ui.form.addEventListener("submit", onSubmit);
  window.addEventListener("hashchange", resumeFromHash);
  resumeFromHash();
}

function setBusy(busy) {
  ui.submit.disabled = busy;
  ui.input.disabled = busy;
  ui.submit.textContent = busy ? "Analisando…" : "Iniciar análise";
  ui.form.setAttribute("aria-busy", String(busy));
}

function showFormError(error) {
  ui.formError.replaceChildren(document.createTextNode(error.message));
  if (error.details && error.details.length) {
    const list = el("ul", {}, error.details.map((d) => el("li", { text: d.message })));
    ui.formError.append(list);
  }
  show(ui.formError);
}

async function onSubmit(event) {
  event.preventDefault();
  show(ui.formError, false);
  const value = ui.input.value.trim();
  if (!value) {
    showFormError(new ApiError("Informe a URL de um repositório público do GitHub."));
    ui.input.focus();
    return;
  }
  setBusy(true);
  clearResults();
  try {
    const accepted = await api.start(value);
    history.replaceState(null, "", `#${accepted.analysis_id}`);
    await follow(accepted.analysis_id);
  } catch (error) {
    if (error.code === "validation_error" || error.status === 413) {
      showFormError(error);
      show(ui.statusCard, false);
    } else {
      showStatusError(error.message);
    }
  } finally {
    setBusy(false);
  }
}

function resumeFromHash() {
  const id = location.hash.slice(1);
  if (!UUID_PATTERN.test(id)) return;
  setBusy(true);
  clearResults();
  follow(id)
    .catch((error) => showStatusError(error.message))
    .finally(() => setBusy(false));
}

/* --- Acompanhamento ---------------------------------------------------------- */

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function follow(id) {
  const token = ++pollToken;
  const startedAt = Date.now();
  show(ui.statusCard);
  while (token === pollToken) {
    let status;
    try {
      status = await api.status(id);
    } catch (error) {
      if (error.status === 404) {
        throw new ApiError("Análise não encontrada ou expirada. Inicie uma nova análise.");
      }
      throw error;
    }
    renderStatus(status);
    if (status.status === "completed") {
      const report = await api.report(id);
      if (token === pollToken) {
        renderReport(report);
        if (report.overall_status === "failed") {
          showStatusError(
            `A análise terminou com falha: ${(report.errors || [])[0] || "veja os detalhes abaixo."}`,
          );
        }
      }
      return;
    }
    if (status.status === "failed") return;
    if (Date.now() - startedAt > MAX_POLL_DURATION_MS) {
      throw new ApiError(
        "A consulta foi interrompida por tempo. A análise pode continuar no servidor; recarregue a página para verificar.",
      );
    }
    await sleep(POLL_INTERVAL_MS);
  }
}

function renderStatus(status) {
  const info = JOB_STATUS[status.status] || { label: status.status, tone: "neutral" };
  ui.statusBadge.className = `badge ${info.tone}`;
  ui.statusBadge.textContent = info.label;

  const order = ["queued", "running", "done"];
  const current = status.status === "queued" ? 0 : status.status === "running" ? 1 : 2;
  for (const item of ui.steps.querySelectorAll("li")) {
    const index = order.indexOf(item.dataset.step);
    item.classList.toggle("done", index < current || (index === 2 && status.status === "completed"));
    item.classList.toggle("active", index === current && status.status !== "completed");
    item.classList.toggle("error", index === 2 && status.status === "failed");
  }

  const messages = {
    queued: "A análise está na fila e começará em breve.",
    running: "Clonando o repositório e executando as verificações…",
    completed: "Análise concluída. Os resultados estão abaixo.",
    failed: status.error || "A análise falhou e não produziu relatório.",
  };
  ui.statusMessage.className = `status-message ${status.status === "failed" ? "error" : ""}`;
  ui.statusMessage.textContent = messages[status.status] || "";

  ui.statusDetails.replaceChildren(
    ...definitionList([
      ["Repositório", safeLink(status.repository_url, status.repository_url)],
      ["Identificador", el("code", { text: status.analysis_id })],
      ["Criada em", formatDate(status.created_at)],
      ["Finalizada em", status.finished_at ? formatDate(status.finished_at) : null],
    ]).childNodes,
  );
  show(ui.statusCard);
}

function showStatusError(message) {
  show(ui.statusCard);
  ui.statusBadge.className = "badge danger";
  ui.statusBadge.textContent = "Falhou";
  const last = ui.steps.querySelector('li[data-step="done"]');
  last.classList.remove("done", "active");
  last.classList.add("error");
  ui.statusMessage.className = "status-message error";
  ui.statusMessage.textContent = message;
}

function clearResults() {
  ui.results.replaceChildren();
  show(ui.results, false);
}

/* --- Relatório ----------------------------------------------------------------- */

function renderReport(report) {
  ui.results.replaceChildren(
    renderSummary(report),
    renderChecks(report),
    renderQuality(report.quality),
    renderRuff(report.ruff),
    renderDependencies(report.dependencies),
    renderTests(report.tests),
  );
  show(ui.results);
}

function renderSummary(report) {
  const overall = OVERALL_STATUS[report.overall_status] || { label: report.overall_status, tone: "neutral" };
  const counts = report.finding_counts || {};
  const quality = report.quality;
  const tools = report.tools || {};

  const metrics = el(
    "div",
    { class: "metrics" },
    metric("Pontuação", quality && quality.score !== null ? formatNumber(quality.score, 1) : "Indisponível"),
    metric("Achados do Ruff", formatNumber(counts.ruff_findings)),
    metric("Vulnerabilidades", formatNumber(counts.vulnerabilities)),
    metric("Dependências não auditadas", formatNumber(counts.unaudited_dependencies)),
  );

  const reportUrl = `/analyses/${encodeURIComponent(report.analysis_id)}/report`;
  const download = el("button", { type: "button", class: "button", text: "Baixar JSON" });
  download.addEventListener("click", () => downloadJson(report));

  return el(
    "section",
    { class: "card" },
    el(
      "div",
      { class: "status-header" },
      el("h2", { text: "Resumo" }),
      badge(overall.label, overall.tone),
    ),
    el("p", { class: "lead", text: overall.lead || "" }),
    metrics,
    definitionList([
      ["Repositório", report.repository ? safeLink(report.repository.url, report.repository.url) : "—"],
      ["Início", formatDate(report.started_at)],
      ["Duração", `${formatNumber(report.duration_seconds, 1)} s`],
      [
        "Ferramentas",
        [
          `CodeGuardian ${tools.codeguardian || "—"}`,
          `Python ${tools.python || "—"}`,
          `Git ${tools.git || "—"}`,
          `Ruff ${tools.ruff || "—"}`,
          `pip-audit ${tools.pip_audit || "—"}`,
          tools.docker ? `Docker ${tools.docker}` : null,
        ]
          .filter(Boolean)
          .join(" · "),
      ],
    ]),
    renderMessages(report.errors, "danger", "Erros"),
    renderMessages(report.warnings, "warning", "Avisos"),
    el(
      "div",
      { class: "actions" },
      el("a", { class: "button", href: reportUrl, target: "_blank", rel: "noopener", text: "Abrir relatório JSON" }),
      download,
    ),
  );
}

function metric(label, value) {
  return el("div", { class: "metric" }, el("span", { class: "metric-value", text: value }), el("span", { class: "metric-label", text: label }));
}

function renderMessages(items, tone, title) {
  if (!items || !items.length) return null;
  return el(
    "div",
    { class: `message ${tone}` },
    el("strong", { text: title }),
    el("ul", {}, items.map((item) => el("li", { text: item }))),
  );
}

function downloadJson(report) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = el("a", { href: url, download: `codeguardian-${report.analysis_id}.json` });
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function renderChecks(report) {
  const rows = (report.checks || []).map((check) => {
    const info = CHECK_STATUS[check.status] || { label: check.status, tone: "neutral" };
    return [
      CHECK_NAMES[check.name] || check.name,
      badge(info.label, info.tone),
      check.finding_count === null || check.finding_count === undefined ? "—" : formatNumber(check.finding_count),
      check.message || "",
    ];
  });
  return section("Verificações", table(["Verificação", "Status", "Achados", "Observação"], rows, "Status de cada verificação"));
}

function renderQuality(quality) {
  if (!quality) return section("Pontuação", notice("Pontuação não disponível neste relatório.", "neutral"));
  const header = el(
    "div",
    { class: "score-header" },
    el("span", { class: "score-value", text: quality.score !== null ? formatNumber(quality.score, 1) : "—" }),
    el(
      "div",
      {},
      badge((SCORE_STATUS[quality.status] || {}).label || quality.status, (SCORE_STATUS[quality.status] || {}).tone),
      quality.reason ? el("p", { class: "muted", text: quality.reason }) : null,
    ),
  );
  const dimensions = (quality.dimensions || []).map((dimension) => {
    const info = SCORE_STATUS[dimension.status] || { label: dimension.status, tone: "neutral" };
    return el(
      "details",
      { class: "dimension" },
      el(
        "summary",
        {},
        el("span", { class: "dimension-name", text: DIMENSION_NAMES[dimension.name] || dimension.name }),
        el("span", { class: "dimension-score", text: dimension.score !== null ? formatNumber(dimension.score, 1) : "—" }),
        badge(info.label, info.tone),
        el("span", {
          class: "muted",
          text:
            dimension.effective_weight !== null
              ? `peso ${formatNumber(dimension.effective_weight * 100, 1)}%`
              : `peso ${dimension.weight} (fora da média)`,
        }),
      ),
      dimension.reason ? el("p", { class: "muted", text: dimension.reason }) : null,
      dimension.factors && dimension.factors.length
        ? el(
            "ul",
            { class: "factors" },
            dimension.factors.map((factor) =>
              el(
                "li",
                {},
                el("span", { class: factor.impact < 0 ? "impact negative" : "impact", text: factor.impact < 0 ? formatNumber(factor.impact, 1) : "·" }),
                el("span", { text: factor.description }),
              ),
            ),
          )
        : null,
    );
  });
  return section(
    "Pontuação explicável",
    header,
    el("p", { class: "message neutral", text: quality.disclaimer }),
    ...dimensions,
    el("p", { class: "muted small", text: `Fórmula ${quality.formula_version}. Clique em cada dimensão para ver os fatores.` }),
  );
}

function renderRuff(ruff) {
  if (!ruff) return section("Análise estática (Ruff)", notice("O Ruff não foi executado.", "neutral"));
  const parts = [
    definitionList([
      ["Status", RUFF_STATUS[ruff.status] || ruff.status],
      ["Regras", (ruff.rules || []).join(", ")],
      ["Achados", formatNumber(ruff.finding_count)],
      ["Versão", ruff.tool_version],
    ]),
  ];
  if (ruff.error) parts.push(notice(ruff.error, "danger"));
  if (ruff.findings_truncated) {
    parts.push(notice(`Apenas ${formatNumber(ruff.findings.length)} de ${formatNumber(ruff.finding_count)} achados foram detalhados.`, "warning"));
  }
  const findings = ruff.findings || [];
  if (ruff.status === "completed" && !findings.length) {
    parts.push(notice("Nenhum achado nas regras verificadas.", "success"));
  }
  if (findings.length) {
    parts.push(renderRuleChart(findings), renderFindingsTable(findings));
  }
  return section("Análise estática (Ruff)", ...parts);
}

function renderRuleChart(findings) {
  const counts = new Map();
  for (const finding of findings) {
    const rule = finding.rule || "(sem regra)";
    counts.set(rule, (counts.get(rule) || 0) + 1);
  }
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
  const max = top.length ? top[0][1] : 1;
  return el(
    "div",
    { class: "chart", role: "img", "aria-label": "Regras mais frequentes nos achados detalhados" },
    el("h3", { text: "Regras mais frequentes" }),
    top.map(([rule, count]) => {
      const fill = el("span", { class: "bar-fill" });
      // Via CSSOM: o CSP da página bloqueia atributos style inline.
      fill.style.width = `${Math.max(2, (count / max) * 100)}%`;
      return el(
        "div",
        { class: "bar-row" },
        el("span", { class: "bar-label", text: rule }),
        el("span", { class: "bar" }, fill),
        el("span", { class: "bar-value", text: formatNumber(count) }),
      );
    }),
  );
}

function renderFindingsTable(findings) {
  const container = el("div", { class: "findings" });
  const filter = el("input", {
    type: "search",
    placeholder: "Filtrar por arquivo, regra ou descrição",
    "aria-label": "Filtrar achados",
    class: "filter",
  });
  const summary = el("p", { class: "muted small", "aria-live": "polite" });
  const body = el("tbody");
  const more = el("button", { type: "button", class: "button", text: "Mostrar mais" });
  let visible = FINDINGS_PAGE_SIZE;

  function matches(finding, term) {
    if (!term) return true;
    return [finding.file, finding.rule, finding.message, finding.suggestion]
      .filter(Boolean)
      .some((value) => value.toLowerCase().includes(term));
  }

  function update() {
    const term = filter.value.trim().toLowerCase();
    const filtered = findings.filter((finding) => matches(finding, term));
    const page = filtered.slice(0, visible);
    body.replaceChildren(
      ...page.map((finding) =>
        el(
          "tr",
          {},
          el("td", {}, el("code", { text: finding.file })),
          el("td", { class: "num", text: `${finding.line}:${finding.column}` }),
          el("td", {}, finding.url ? safeLink(finding.url, finding.rule || "—") : el("span", { text: finding.rule || "—" })),
          el(
            "td",
            {},
            el("span", { text: finding.message }),
            finding.suggestion ? el("span", { class: "suggestion", text: `Sugestão: ${finding.suggestion}` }) : null,
          ),
        ),
      ),
    );
    summary.textContent = filtered.length
      ? `Exibindo ${formatNumber(page.length)} de ${formatNumber(filtered.length)} achado(s).`
      : "Nenhum achado corresponde ao filtro.";
    show(more, filtered.length > page.length);
  }

  filter.addEventListener("input", () => {
    visible = FINDINGS_PAGE_SIZE;
    update();
  });
  more.addEventListener("click", () => {
    visible += FINDINGS_PAGE_SIZE;
    update();
  });

  const head = el("thead", {}, el("tr", {}, ["Arquivo", "Linha", "Regra", "Descrição"].map((h) => el("th", { scope: "col", text: h }))));
  append(container, [
    el("h3", { text: "Problemas encontrados" }),
    filter,
    summary,
    el("div", { class: "table-wrap" }, el("table", {}, head, body)),
    more,
  ]);
  update();
  return container;
}

function renderDependencies(audit) {
  const title = "Dependências (pip-audit)";
  if (!audit) return section(title, notice("A auditoria de dependências não foi executada.", "neutral"));
  const tone =
    audit.status === "vulnerabilities_found"
      ? "warning"
      : audit.status === "no_vulnerabilities"
        ? "success"
        : ["no_dependency_files", "no_auditable_dependencies"].includes(audit.status)
          ? "neutral"
          : "danger";
  const parts = [
    notice(AUDIT_STATUS[audit.status] || audit.status, tone),
    definitionList([
      ["Arquivos", (audit.dependency_files || []).map((f) => f.path).join(", ") || "—"],
      ["Pacotes auditados", formatNumber((audit.packages || []).length)],
      ["Pacotes vulneráveis", formatNumber(audit.vulnerable_package_count)],
      ["Fonte", audit.vulnerability_service],
      ["Versão", audit.tool_version],
    ]),
  ];
  if (audit.error) parts.push(notice(audit.error, "danger"));

  const vulnerable = (audit.packages || []).filter((p) => p.vulnerabilities && p.vulnerabilities.length);
  if (vulnerable.length) {
    const rows = [];
    for (const pkg of vulnerable) {
      for (const vuln of pkg.vulnerabilities) {
        rows.push([
          el("strong", { text: pkg.name }),
          pkg.version,
          safeLink(`https://osv.dev/vulnerability/${encodeURIComponent(vuln.id)}`, vuln.id),
          (vuln.aliases || []).join(", ") || "—",
          (vuln.fix_versions || []).join(", ") || "sem correção informada",
          (pkg.sources || []).join(", "),
        ]);
      }
    }
    parts.push(
      el("h3", { text: "Vulnerabilidades conhecidas" }),
      table(["Pacote", "Versão", "Identificador", "Aliases", "Corrigida em", "Origem"], rows, "Vulnerabilidades por pacote"),
    );
  }
  const unaudited = audit.unaudited || [];
  if (unaudited.length) {
    parts.push(
      el(
        "details",
        { class: "collapsible" },
        el("summary", { text: `Não auditadas (${formatNumber(unaudited.length)})` }),
        table(
          ["Origem", "Linha", "Declaração", "Motivo"],
          unaudited.map((u) => [u.source, u.line ? String(u.line) : "—", el("code", { text: u.requirement }), u.reason]),
          "Dependências não auditadas",
        ),
      ),
    );
  }
  if ((audit.collection_errors || []).length) parts.push(renderMessages(audit.collection_errors, "warning", "Arquivos com problemas"));
  return section(title, ...parts);
}

function renderTests(tests) {
  const title = "Testes (pytest isolado)";
  if (!tests) return section(title, notice("A execução de testes não foi realizada.", "neutral"));
  const counts = tests.counts;
  const tone = tests.status === "passed" ? "success" : tests.status === "failed" ? "warning" : ["disabled", "no_tests"].includes(tests.status) ? "neutral" : "danger";
  return section(
    title,
    notice(TEST_STATUS[tests.status] || tests.status, tone),
    tests.message ? el("p", { class: "muted", text: tests.message }) : null,
    counts
      ? definitionList([
          ["Aprovados", formatNumber(counts.passed)],
          ["Reprovados", formatNumber(counts.failed)],
          ["Erros", formatNumber(counts.errors)],
          ["Ignorados", formatNumber(counts.skipped)],
        ])
      : null,
  );
}

document.addEventListener("DOMContentLoaded", init);
