"use strict";
/**
 * app.js
 * PhishGuard 프론트엔드 — API 호출, 결과 렌더링, 테마 전환
 *
 * 주요 기능:
 *   1. POST /analyze 호출 + 로딩 스피너(스캔 애니메이션)
 *   2. 위험도 게이지 바 애니메이션 (0→최종 점수)
 *   3. 모듈별 점수 분해 바
 *   4. 탐지 항목 카드 렌더링
 *   5. 원문 키워드/URL 형광펜 하이라이트
 *   6. 레벨에 따른 색상 변환
 *   7. [신규] 라이트/다크 모드 토글 — body.dark-mode 클래스 + localStorage 저장
 *
 * 보안 설계:
 *   - textContent 사용 (innerHTML 직접 사용 금지 — XSS 방어)
 *   - 하이라이트 시 값 이스케이프 처리
 *   - 입력 1000자 제한 (서버와 동일 기준)
 */

const API_BASE = "";
// const API_BASE = "http://localhost:8000";

// ── 샘플 문자 ──────────────────────────────────────────
const SAMPLES = {
  smishing: `[국민은행] 고객님의 계좌가 일시 정지되었습니다. 즉시 본인확인 후 해제하세요.
주민등록번호와 카드번호를 입력해 본인인증을 완료하세요: http://bit.ly/kb-auth99`,

  normal: `안녕하세요! 내일 오전 10시에 회의실 A로 모여주세요.
회의 자료는 이메일로 발송드렸습니다. 궁금한 점 있으면 연락주세요.`,
};

// ── 탐지 타입 한국어 레이블 ────────────────────────────
// 고령층·정보 취약계층이 이해하기 쉬운 말로 변경
const TYPE_LABELS = {
  URL:           "위험한 인터넷 주소",   // 기존: "악성 URL"
  short_url:     "짧은 인터넷 주소",    // 기존: "단축 URL"
  keyword:       "의심 단어",           // 기존: "위험 키워드"
  personal_info: "개인정보 요구",        // 유지
  phone_lure:    "전화 유도",           // 유지
};

// ── DOM 요소 캐싱 ──────────────────────────────────────
const $ = (id) => document.getElementById(id);

const els = {
  input:           $("msgInput"),
  analyzeBtn:      $("analyzeBtn"),
  charCount:       $("charCount"),
  scanOverlay:     $("scanOverlay"),
  resultSection:   $("resultSection"),
  scoreDisplay:    $("scoreDisplay"),
  gaugeFill:       $("gaugeFill"),
  levelBadge:      $("levelBadge"),
  ruleBar:         $("ruleBar"),
  mlBar:           $("mlBar"),
  llmBar:          $("llmBar"),
  ruleScore:       $("ruleScore"),
  mlScore:         $("mlScore"),
  llmScore:        $("llmScore"),
  llmRow:          $("llmRow"),
  llmCard:         $("llmCard"),
  llmReason:       $("llmReason"),
  detectedCard:    $("detectedCard"),
  detectedCount:   $("detectedCount"),
  detectedList:    $("detectedList"),
  highlightCard:   $("highlightCard"),
  highlightedText: $("highlightedText"),
  adviceCard:      $("adviceCard"),
  adviceText:      $("adviceText"),
  scoreCard:       $("scoreCard"),
  themeToggle:     $("themeToggle"),
  themeIcon:       $("themeIcon"),
};

// ════════════════════════════════════════════════════════
// ── 테마 관리 (라이트 / 다크 모드 전환) ─────────────────
// ════════════════════════════════════════════════════════

/**
 * localStorage 키: 사용자 선택 테마를 저장
 * "dark"  → 다크 모드
 * "light" → 라이트 모드 (기본)
 * 값 없음 → 라이트 모드 (기본)
 */
const THEME_KEY = "phishguard_theme";

/**
 * 현재 테마를 body 클래스와 버튼 아이콘에 적용
 * @param {boolean} isDark - true면 다크 모드
 */
function applyTheme(isDark) {
  if (isDark) {
    // 다크 모드: body에 dark-mode 클래스 추가
    document.body.classList.add("dark-mode");
    // 아이콘: 라이트 모드로 전환하는 버튼이므로 ☀️
    els.themeIcon.textContent = "☀️";
    // 툴팁 텍스트 업데이트
    els.themeToggle.setAttribute("aria-label", "라이트 모드로 전환");
    els.themeToggle.setAttribute("title", "라이트 모드로 전환");
    // 스캔 텍스트: 다크 모드에서는 영문
    const scanText = document.querySelector(".scan-text");
    if (scanText) scanText.textContent = "SCANNING...";
  } else {
    // 라이트 모드: dark-mode 클래스 제거
    document.body.classList.remove("dark-mode");
    // 아이콘: 다크 모드로 전환하는 버튼이므로 🌙
    els.themeIcon.textContent = "🌙";
    // 툴팁 텍스트 업데이트
    els.themeToggle.setAttribute("aria-label", "다크 모드로 전환");
    els.themeToggle.setAttribute("title", "다크 모드로 전환");
    // 스캔 텍스트: 라이트 모드에서는 한국어
    const scanText = document.querySelector(".scan-text");
    if (scanText) scanText.textContent = "분석 중...";
  }
}

/**
 * 테마 전환 버튼 클릭 핸들러
 * 현재 상태를 반전하고 localStorage에 저장
 */
function toggleTheme() {
  // 현재 다크 모드 여부 확인
  const isDarkNow = document.body.classList.contains("dark-mode");
  const newIsDark = !isDarkNow;

  // 테마 적용
  applyTheme(newIsDark);

  // localStorage에 저장 (새로고침 후에도 유지)
  try {
    localStorage.setItem(THEME_KEY, newIsDark ? "dark" : "light");
  } catch (e) {
    // localStorage 접근 실패 시 무시 (프라이빗 모드 등)
    console.warn("localStorage 저장 실패:", e);
  }
}

/**
 * 페이지 로드 시 저장된 테마 복원
 * 저장값 없으면 라이트 모드(기본)
 */
function initTheme() {
  let saved = null;
  try {
    saved = localStorage.getItem(THEME_KEY);
  } catch (e) {
    // localStorage 읽기 실패 시 무시
  }

  // "dark" 로 저장된 경우에만 다크 모드 적용, 그 외 모두 라이트 모드
  applyTheme(saved === "dark");
}

// 페이지 로드 즉시 테마 초기화
initTheme();

// ════════════════════════════════════════════════════════
// ── 이하 기존 기능 — 수정 없이 유지 ─────────────────────
// ════════════════════════════════════════════════════════

// ── 글자 수 카운터 ──────────────────────────────────────
els.input.addEventListener("input", () => {
  const len = els.input.value.length;
  els.charCount.textContent = len;
  // 900자 이상이면 노란색으로 경고
  els.charCount.parentElement.classList.toggle("warn", len >= 900);
});

// ── Enter 키로 분석 실행 (Shift+Enter는 줄바꿈) ────────
els.input.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    runAnalysis();
  }
});

// ── 샘플 문자 로드 ─────────────────────────────────────
function loadSample(type) {
  els.input.value = SAMPLES[type] || "";
  els.charCount.textContent = els.input.value.length;
  els.input.focus();
}

// ── HTML 이스케이프 (XSS 방어) ──────────────────────────
// innerHTML에 사용자 입력을 넣기 전에 반드시 이스케이프
function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ── 스캔 오버레이 제어 ─────────────────────────────────
function showScanning()  { els.scanOverlay.classList.add("active");    }
function hideScanning()  { els.scanOverlay.classList.remove("active"); }

// ── 게이지 + 점수 숫자 애니메이션 ──────────────────────
function animateScore(targetScore, level) {
  // 라이트 모드: 진한 색상 / 다크 모드: 네온 색상
  const isDark = document.body.classList.contains("dark-mode");

  const colorMapDark  = { 안전: "#00ff88", 주의: "#ffb300", 위험: "#ff3b3b" };
  const colorMapLight = { 안전: "#2e7d32", 주의: "#f57c00", 위험: "#d32f2f" };
  const colorMap = isDark ? colorMapDark : colorMapLight;
  const color = colorMap[level] || (isDark ? "#4d7cff" : "#1a73e8");

  els.gaugeFill.style.background = color;
  // 다크 모드에서만 네온 글로우 효과
  els.gaugeFill.style.boxShadow  = isDark ? `0 0 10px ${color}` : "none";
  els.gaugeFill.style.width      = `${targetScore}%`;

  // 숫자 카운트업 (0 → targetScore, 800ms)
  const duration = 800;
  const start    = performance.now();

  function tick(now) {
    const elapsed  = now - start;
    const progress = Math.min(elapsed / duration, 1);
    // easeOutCubic
    const eased    = 1 - Math.pow(1 - progress, 3);
    const current  = Math.round(eased * targetScore);
    els.scoreDisplay.textContent = current;
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);

  // 점수 색상
  els.scoreDisplay.style.color = color;
}

// ── 모듈별 점수 바 렌더링 ──────────────────────────────
function renderBreakdown(data) {
  els.ruleBar.style.width   = `${data.rule_score}%`;
  els.mlBar.style.width     = `${data.ml_score}%`;
  els.ruleScore.textContent = `${data.rule_score}`;
  els.mlScore.textContent   = `${data.ml_score}`;

  if (data.llm_used && data.llm_score != null) {
    els.llmRow.hidden        = false;
    els.llmBar.style.width   = `${data.llm_score}%`;
    els.llmScore.textContent = `${data.llm_score}`;
  } else {
    els.llmRow.hidden = true;
  }
}

// ── 레벨 뱃지 렌더링 ──────────────────────────────────
function renderLevelBadge(level) {
  const classMap = { 안전: "safe", 주의: "warn", 위험: "danger" };
  els.levelBadge.textContent = level;
  els.levelBadge.className   = `level-badge ${classMap[level] || ""}`;
}

// ── 탐지 항목 카드 렌더링 ──────────────────────────────
function renderDetected(detected) {
  if (!detected || detected.length === 0) {
    els.detectedCard.hidden = true;
    return;
  }

  els.detectedCard.hidden       = false;
  els.detectedCount.textContent = `${detected.length}건`;
  els.detectedList.innerHTML    = ""; // 초기화

  detected.forEach((item, idx) => {
    const div = document.createElement("div");
    div.className = "detected-item";
    div.style.animationDelay = `${idx * 60}ms`;

    // 타입 뱃지
    const typeBadge = document.createElement("span");
    typeBadge.className   = `detected-type type-${item.type}`;
    typeBadge.textContent = TYPE_LABELS[item.type] || item.type;

    // 내용
    const content = document.createElement("div");
    content.className = "detected-content";

    const value = document.createElement("div");
    value.className   = "detected-value";
    value.textContent = item.value; // textContent — XSS 방어

    const reason = document.createElement("div");
    reason.className   = "detected-reason";
    reason.textContent = item.reason;

    content.appendChild(value);
    content.appendChild(reason);
    div.appendChild(typeBadge);
    div.appendChild(content);
    els.detectedList.appendChild(div);
  });
}

// ── 원문 하이라이트 렌더링 ─────────────────────────────
// 탐지된 값들을 원문에서 찾아 <mark> 태그로 강조
function renderHighlight(originalText, detected) {
  if (!detected || detected.length === 0) {
    els.highlightCard.hidden = true;
    return;
  }

  els.highlightCard.hidden = false;

  // 이스케이프된 텍스트로 시작
  let escaped = escapeHtml(originalText);

  // 각 탐지 항목을 순서대로 하이라이트 (긴 것부터 처리해 중첩 방지)
  const sorted = [...detected].sort(
    (a, b) => b.value.length - a.value.length
  );

  sorted.forEach((item) => {
    const safeVal = escapeHtml(item.value);
    if (!safeVal) return;

    // 이스케이프된 문자열에서 치환
    const regex = new RegExp(
      safeVal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), // 정규식 특수문자 이스케이프
      "g"
    );
    escaped = escaped.replace(
      regex,
      `<mark class="hl-${item.type}">${safeVal}</mark>`
    );
  });

  // innerHTML 사용하지만 escapeHtml + 제한된 태그만 허용
  els.highlightedText.innerHTML = escaped;
}

// ── LLM 설명 렌더링 ────────────────────────────────────
function renderLlm(data) {
  if (data.llm_used && data.llm_reason) {
    els.llmCard.hidden        = false;
    els.llmReason.textContent = data.llm_reason; // textContent — XSS 방어
  } else {
    els.llmCard.hidden = true;
  }
}

// ── 대처법 카드 렌더링 ─────────────────────────────────
function renderAdvice(advice, level) {
  const classMap = { 안전: "safe-advice", 주의: "warn-advice", 위험: "danger-advice" };
  els.adviceCard.className   = `advice-card ${classMap[level] || ""}`;
  els.adviceText.textContent = advice;
}

// ── 오류 표시 ──────────────────────────────────────────
function showError(msg) {
  els.resultSection.hidden = false;
  els.scoreCard.innerHTML  = `
    <div style="text-align:center; padding: 20px 0; color: var(--danger); font-family: var(--mono);">
      ⚠ ${escapeHtml(msg)}
    </div>`;
}

// ── UI 초기화 ──────────────────────────────────────────
function resetUI() {
  els.resultSection.hidden      = true;
  els.input.value               = "";
  els.charCount.textContent     = "0";
  els.input.focus();

  // 카드들 숨기기
  els.llmCard.hidden            = true;
  els.detectedCard.hidden       = true;
  els.highlightCard.hidden      = true;
  els.gaugeFill.style.width     = "0%";
  els.scoreDisplay.textContent  = "0";
  els.levelBadge.textContent    = "—";
  els.levelBadge.className      = "level-badge";
}

// ── 메인: 분석 실행 ────────────────────────────────────
async function runAnalysis() {
  const text = els.input.value.trim();

  // 클라이언트 측 기본 검증
  if (!text) {
    els.input.focus();
    els.input.style.borderColor = "var(--danger)";
    setTimeout(() => { els.input.style.borderColor = ""; }, 1500);
    return;
  }

  if (text.length > 1000) {
    alert("문자는 최대 1000자까지 분석 가능합니다.");
    return;
  }

  // UI 상태: 분석 중
  els.analyzeBtn.disabled      = true;
  els.resultSection.hidden     = true;
  showScanning();

  try {
    const resp = await fetch(`${API_BASE}/analyze`, {
      method:      "POST",
      headers:     {
        "Content-Type": "application/json",
        "ngrok-skip-browser-warning": "true",  // ngrok 무료 버전 경고 페이지 건너뛰기
      },
      credentials: "omit",
      body:        JSON.stringify({ text }),
    });

    if (!resp.ok) {
      let errMsg = `서버 오류 (HTTP ${resp.status})`;
      try {
        const errData = await resp.json();
        errMsg = errData.detail || errMsg;
      } catch (_) {}
      throw new Error(errMsg);
    }

    const data = await resp.json();

    // 스캔 애니메이션 종료 + 결과 표시
    hideScanning();
    els.resultSection.hidden = false;

    // 순서대로 렌더링
    renderLevelBadge(data.level);
    animateScore(data.score, data.level);
    renderBreakdown(data);
    renderLlm(data);
    renderDetected(data.detected);
    renderHighlight(text, data.detected);
    renderAdvice(data.advice, data.level);

    // 결과 섹션으로 스크롤
    setTimeout(() => {
      els.resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 100);

  } catch (err) {
    hideScanning();
    if (err.name === "TypeError") {
      showError("서버에 연결할 수 없습니다. 백엔드가 실행 중인지 확인하세요 (localhost:8000)");
    } else {
      showError(err.message || "알 수 없는 오류가 발생했습니다.");
    }
  } finally {
    els.analyzeBtn.disabled = false;
  }
}