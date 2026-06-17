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
"""

import re
import os
import httpx
import asyncio
from typing import TypedDict

# ─────────────────────────────────────────────
# 타입 정의
# ─────────────────────────────────────────────

class DetectedItem(TypedDict):
    type: str    # "URL" | "short_url" | "keyword" | "personal_info"
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
# 2. 단축 URL 도메인 목록
# ─────────────────────────────────────────────
# 피싱 공격자들이 악성 URL을 숨기기 위해 단축 URL을 자주 사용함
SHORT_URL_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "tiny.cc", "lnkd.in",
    "db.tt", "qr.ae", "po.st", "bc.vc", "s.id",
    "cutt.ly", "rebrand.ly", "short.io", "han.gl", "me2.do",
}

# ─────────────────────────────────────────────
# 3. 긴급성 유도 키워드
# ─────────────────────────────────────────────
# 심리적 압박으로 피해자가 URL을 클릭하게 유도하는 표현들
# 출처: KISA(한국인터넷진흥원) 스미싱 유형 분석 보고서 참조
URGENCY_KEYWORDS = [
    # 즉각 행동 유도
    "즉시", "지금 바로", "빨리", "당장", "긴급",
    # 계좌/금융 관련 공포 자극
    "계좌 정지", "계좌정지", "출금 정지", "카드 정지", "이용 정지",
    "거래 중단", "대출 승인", "대출승인",
    "정지되었습니다", "제한되었습니다", "동결되었습니다",  # 추가
    "정책에 의해", "이용 제한", "서비스 중단",              # 추가
    # 본인 확인 사칭
    "본인 확인", "본인확인", "인증 필요", "인증번호", "ARS 인증",
    # 클릭/접속 유도
    "클릭", "접속 요망", "지금 확인", "바로 확인", "즉각 확인",
    # 수령/당첨 미끼
    "수령하세요", "당첨되었습니다", "지급 예정", "환급금",
    "미수령", "택배 미수령", "반송 예정",
    # 기관 사칭
    "건강보험", "국세청", "경찰청", "검찰청", "금융감독원",
    "우체국", "카카오페이", "네이버페이",
    # 법적 위협
    "법적 조치", "고소", "벌금", "과태료",
    # 연락 유도 (전화번호와 결합 시 위험도 상승)  # 추가
    "연락 바랍니다", "연락주세요", "전화 바람", "회신 바랍니다",  # 추가
]

# ─────────────────────────────────────────────
# 4. 개인정보 요구 패턴
# ─────────────────────────────────────────────
# 정규식으로 개인정보 수집 시도를 탐지
PERSONAL_INFO_PATTERNS = [
    (re.compile(r'주민\s*등록\s*번호|주민번호|생년월일'), "주민등록번호 요구"),
    (re.compile(r'카드\s*번호|신용카드|체크카드\s*번호'), "카드번호 요구"),
    (re.compile(r'비밀\s*번호|패스워드|password', re.IGNORECASE), "비밀번호 요구"),
    (re.compile(r'계좌\s*번호|통장\s*번호'), "계좌번호 요구"),
    (re.compile(r'공인인증서|금융\s*인증서|OTP'), "금융 인증 정보 요구"),
    (re.compile(r'CVC|CVV|카드\s*뒷\s*3자리'), "카드 보안코드 요구"),
]

# ─────────────────────────────────────────────
# 5. 가중치 설정 (합계가 rule_score 100점 기준)
# ─────────────────────────────────────────────
WEIGHTS = {
    "virustotal_malicious": 50,  # VirusTotal 악성 판정 — 가장 강력한 신호
    "short_url": 15,             # 단축 URL — URL 숨김 의도
    "urgency_keyword": 10,       # 긴급성 키워드 1개당 (최대 30점)
    "personal_info": 20,         # 개인정보 요구 패턴 1개당 (최대 40점)
    "url_exists": 5,             # URL 존재 자체도 약한 신호
    "phone_lure": 15,  # 추가: 전화번호 유도 패턴
}
# ─────────────────────────────────────────────
# 6. 전화번호 유도 패턴 (신규)
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
            if domain in SHORT_URL_DOMAINS:
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
    for keyword in URGENCY_KEYWORDS:
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
    for pattern, reason in PERSONAL_INFO_PATTERNS:
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