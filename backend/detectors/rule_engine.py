"""
rule_engine.py
규칙 기반 피싱 탐지 모듈

탐지 항목:
  1. URL 추출 (정규식)
  2. 단축 URL 탐지
  3. 긴급성 키워드 탐지
  4. 개인정보 요구 패턴 탐지
  5. VirusTotal API 악성 URL 조회
  6. 가중치 기반 점수 산출 (0~100)

보안 설계 원칙:
  - VirusTotal API 키는 환경변수로만 관리 (하드코딩 금지)
  - URL은 최대 2000자까지만 처리 (ReDoS 방어)
  - 외부 API 실패 시 graceful degradation (점수에서 제외 후 계속 진행)
  - 키워드/도메인/패턴 데이터는 SQLite DB에서 로드 (db_loader.py 참조)
"""

import re
import os
import httpx
from typing import TypedDict

# DB 캐시 접근 함수 임포트
from database.db_loader import get_cached_rules


# ─────────────────────────────────────────────
# 타입 정의
# ─────────────────────────────────────────────

class DetectedItem(TypedDict):
    type: str    # "URL" | "short_url" | "keyword" | "personal_info" | "phone_lure"
    value: str   # 탐지된 실제 값
    reason: str  # 사람이 읽을 수 있는 이유 설명


class RuleResult(TypedDict):
    rule_score: int                  # 0~100
    detected: list[DetectedItem]     # 탐지된 항목 목록


# ─────────────────────────────────────────────
# 1. URL 추출 패턴
# ─────────────────────────────────────────────
# 보안 이유: URL 길이를 2000자로 제한 — 매우 긴 URL로 정규식 엔진을
#            과부하시키는 ReDoS(정규식 서비스 거부) 공격 방어
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\']{1,2000}|'   # http/https URL
    r'www\.[^\s<>"\']{1,2000}',        # www. 로 시작하는 URL
    re.IGNORECASE
)

# ─────────────────────────────────────────────
# 2. 가중치 설정 (합계가 rule_score 100점 기준)
# ─────────────────────────────────────────────
WEIGHTS = {
    "virustotal_malicious": 50,  # VirusTotal 악성 판정 — 가장 강력한 신호
    "short_url":            15,  # 단축 URL — URL 숨김 의도
    "urgency_keyword":      10,  # 긴급성 키워드 1개당 (최대 30점)
    "personal_info":        20,  # 개인정보 요구 패턴 1개당 (최대 40점)
    "url_exists":            5,  # URL 존재 자체도 약한 신호
    "phone_lure":           15,  # 전화번호 유도 패턴
}

# ─────────────────────────────────────────────
# 3. 전화번호 유도 패턴
# ─────────────────────────────────────────────
# URL 없이 전화번호로 직접 연락을 유도하는 스미싱/보이스피싱 연계형
# 한국 전화번호 형식: 010-XXXX-XXXX, 02-XXX-XXXX, 1588-XXXX 등
PHONE_NUMBER_PATTERN = re.compile(
    r'0\d{1,2}[-.\s]?\d{3,4}[-.\s]?\d{4}|'   # 일반 전화/휴대폰
    r'1\d{3}[-.\s]?\d{4}'                     # 1588, 1577 등 대표번호
)


# ─────────────────────────────────────────────
# VirusTotal API 조회
# ─────────────────────────────────────────────
async def check_virustotal(url: str, api_key: str) -> bool:
    """
    VirusTotal API v3로 URL 악성 여부를 조회한다.

    보안 이유:
      - API 키를 함수 인자로 받아 모듈 전역에 노출하지 않음
      - 타임아웃 10초 설정 — 외부 API 응답 지연으로 인한 서비스 블로킹 방지
      - 악성 엔진이 3개 이상일 때만 '악성'으로 판정 (오탐 최소화)

    Returns:
        True: 악성 URL 확인됨
        False: 안전하거나 조회 실패
    """
    if not api_key:
        return False  # API 키 없으면 이 단계 건너뜀

    # VirusTotal은 URL을 base64url 인코딩해서 식별자로 사용
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    headers = {"x-apikey": api_key}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers
            )
            if resp.status_code == 404:
                # 아직 DB에 없는 URL → 새로 제출 후 판정 불가 (건너뜀)
                return False
            if resp.status_code != 200:
                return False

            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious_count = stats.get("malicious", 0)

            # 3개 이상 보안 엔진이 악성으로 판정해야 신뢰
            return malicious_count >= 3

    except (httpx.TimeoutException, httpx.RequestError, KeyError):
        # 외부 API 오류 — 탐지 불가로 처리하고 계속 진행
        return False


# ─────────────────────────────────────────────
# 메인 탐지 함수
# ─────────────────────────────────────────────
async def analyze_rules(text: str) -> RuleResult:
    """
    규칙 기반으로 문자 메시지를 분석하고 위험 점수를 반환한다.

    Args:
        text: 분석할 문자 메시지 (최대 1000자, 상위에서 검증됨)

    Returns:
        RuleResult: rule_score(0~100)와 detected 항목 목록
    """
    detected: list[DetectedItem] = []
    raw_score = 0  # 가중치 합산 전 원점수

    # ── DB 캐시에서 규칙 데이터 가져오기 ────────
    # 서버 시작 시 load_rules_from_db()로 미리 캐싱된 데이터를 사용
    # (매 요청마다 DB를 조회하지 않으므로 성능에 영향 없음)
    rules = get_cached_rules()
    urgency_keywords       = rules["urgency_keywords"]        # list[dict]
    short_url_domains      = rules["short_url_domains"]       # set[str]
    personal_info_patterns = rules["personal_info_patterns"]  # list[(Pattern, str)]

    # ── 1단계: URL 추출 ──────────────────────────────
    urls = URL_PATTERN.findall(text)
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")

    for url in urls:
        detected.append({
            "type": "URL",
            "value": url[:100],  # 표시용 길이 제한 (UI 깨짐 방지)
            "reason": "문자에서 URL이 발견됨"
        })
        raw_score += WEIGHTS["url_exists"]

        # ── 2단계: 단축 URL 확인 ─────────────────────
        # URL에서 도메인만 추출해서 단축 URL 목록과 대조
        domain_match = re.search(r'(?:https?://)?(?:www\.)?([^/\s]+)', url, re.IGNORECASE)
        if domain_match:
            domain = domain_match.group(1).lower()
            if domain in short_url_domains:
                detected.append({
                    "type": "short_url",
                    "value": url[:100],
                    "reason": f"단축 URL 사용 — 실제 목적지가 숨겨져 있음 ({domain})"
                })
                raw_score += WEIGHTS["short_url"]

        # ── 5단계: VirusTotal API 조회 ───────────────
        # 네트워크 비용이 있으므로 URL이 있을 때만 호출
        if vt_api_key:
            is_malicious = await check_virustotal(url, vt_api_key)
            if is_malicious:
                detected.append({
                    "type": "URL",
                    "value": url[:100],
                    "reason": "VirusTotal 다중 보안 엔진에서 악성 URL로 판정됨"
                })
                raw_score += WEIGHTS["virustotal_malicious"]

    # ── 2.5단계: 전화번호 유도 탐지 ─────────────────
    # URL이 없어도 전화번호로 직접 연락을 유도하는 경우 위험 신호로 처리
    # (보이스피싱 연계형 스미싱에서 흔한 패턴)
    phone_matches = PHONE_NUMBER_PATTERN.findall(text)
    has_contact_lure = any(kw in text for kw in ["연락", "전화", "회신"])

    if phone_matches and has_contact_lure:
        detected.append({
            "type": "phone_lure",
            "value": phone_matches[0],
            "reason": "전화번호로 직접 연락 유도 — 보이스피싱 연계 가능성"
        })
        raw_score += WEIGHTS["phone_lure"]

    # ── 3단계: 긴급성 키워드 탐지 ───────────────────
    # DB에서 로드한 urgency_keywords (list of dict) 순회
    for kw_entry in urgency_keywords:
        keyword = kw_entry["keyword"]
        if keyword in text:
            detected.append({
                "type": "keyword",
                "value": keyword,
                "reason": "심리적 긴급성 유도 표현 — 피해자가 생각 없이 클릭하게 만듦"
            })
            raw_score += WEIGHTS["urgency_keyword"]
            # 키워드 점수 상한: 30점 (과도한 중복 방지)
            if raw_score >= 30 + WEIGHTS["url_exists"] * len(urls):
                break

    # ── 4단계: 개인정보 요구 패턴 ───────────────────
    # DB에서 로드한 personal_info_patterns (list of (Pattern, reason)) 순회
    for pattern, reason in personal_info_patterns:
        match = pattern.search(text)
        if match:
            detected.append({
                "type": "personal_info",
                "value": match.group(),
                "reason": f"개인 금융정보 수집 시도 — {reason}"
            })
            raw_score += WEIGHTS["personal_info"]

    # ── 6단계: 최종 점수 계산 ────────────────────────
    # 원점수를 0~100으로 클램핑
    # (가중치 합산이 100을 초과할 수 있으므로 min으로 상한 설정)
    final_score = min(raw_score, 100)

    return {
        "rule_score": final_score,
        "detected": detected
    }