"""
analyze.py
POST /analyze — 세 탐지 모듈을 통합하는 메인 엔드포인트

처리 흐름:
  1. 입력 검증 (Pydantic 자동 처리)
  2. 규칙 기반 탐지 (rule_engine) → rule_score
  3. ML 모델 예측 (ml_model)      → ml_score
  4. 중간 점수 = rule(30%) + ML(40%) 가중 평균 후 정규화
  5. 중간 점수가 40~70점이면 LLM 호출 → llm_score
  6. 최종 점수 합산 → 위험 레벨 판정 → 대처법 생성
"""

import asyncio
from fastapi import APIRouter, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from config import (
    RATE_LIMIT_PER_MINUTE,
    LLM_CALL_MIN, LLM_CALL_MAX,
    WEIGHT_RULE, WEIGHT_ML, WEIGHT_LLM,
)
from models.schemas import AnalyzeRequest, AnalyzeResponse, DetectedItem
from detectors.rule_engine import analyze_rules
from detectors.ml_model import predict as ml_predict
from detectors.llm_analyzer import analyze_llm

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


# ── 위험 레벨 판정 ──────────────────────────────────────────────────
def get_level(score: int) -> str:
    """
    최종 점수를 세 단계 위험 레벨로 변환한다.
      0~39점   → 안전
      40~69점  → 주의
      70~100점 → 위험
    """
    if score < 40:
        return "안전"
    elif score < 70:
        return "주의"
    else:
        return "위험"


# ── 대처법 생성 ─────────────────────────────────────────────────────
def get_advice(level: str, detected: list[dict]) -> str:
    """
    위험 레벨과 탐지 항목에 맞는 맞춤형 대처법을 반환한다.
    """
    types = {item["type"] for item in detected}
    has_url = "URL" in types or "short_url" in types
    has_phone = "phone_lure" in types

    if level == "위험":
        base = "⛔ 이 문자는 스미싱(피싱)으로 의심됩니다."
        extras = []

        if has_url:
            extras.append("절대 링크를 클릭하지 마세요. 클릭했다면 즉시 해당 앱을 삭제하고 백신 앱으로 검사하세요.")
        if has_phone:
            extras.append("문자에 적힌 번호로 절대 전화하지 마세요. 해당 기관의 공식 대표번호로 직접 확인하세요.")
        if "personal_info" in types:
            extras.append("개인정보나 금융정보를 입력했다면 즉시 해당 기관에 신고하고 비밀번호를 변경하세요.")
        if not has_url and not has_phone and "personal_info" not in types:
            # URL/전화/개인정보 패턴 없이 LLM 판단만으로 위험도가 높게 나온 경우
            extras.append("문자 내용이 의심스럽습니다. 발신자에게 직접 연락하지 말고 사실 여부를 따로 확인하세요.")

        extras.append("한국인터넷진흥원(KISA) 불법스팸대응센터 118로 신고할 수 있습니다.")
        return " ".join([base] + extras)

    elif level == "주의":
        return (
            "⚠️ 이 문자는 일부 위험 요소를 포함하고 있습니다. "
            "발신자를 정확히 확인하고, 공식 앱이나 웹사이트를 직접 방문해 사실 여부를 확인하세요. "
            "의심스러우면 해당 기관 공식 전화번호로 직접 문의하세요."
        )
    else:
        return "✅ 이 문자는 안전한 것으로 판단됩니다. 그래도 출처가 불분명한 링크는 주의하세요."


# ── 점수 통합 계산 ──────────────────────────────────────────────────
def calculate_final_score(
    rule_score: int,
    ml_score: int,
    llm_score: int | None,
) -> int:
    """
    세 모듈의 점수를 가중 평균으로 통합한다.

    LLM 호출 시:   rule×0.30 + ml×0.40 + llm×0.30
    LLM 미호출 시: rule×0.4286 + ml×0.5714  (가중치 재정규화)

    강한 위험 신호 우선 규칙:
      LLM이 90점 이상으로 명확하게 위험 판단을 내렸다면,
      단순 가중 평균으로 점수가 희석되어 위험한 문자가
      "주의"로 과소 분류되는 것을 방지하기 위해
      가중 평균과 LLM 점수 중 더 높은 쪽을 최종 점수로 채택한다.
      (실제 보안 탐지 시스템에서도 강한 단일 신호가 있으면
       전체 위험도를 보수적으로—즉 위험 쪽으로—재평가하는 방식을 사용함)
    """
    if llm_score is not None:
        weighted = (
            rule_score * WEIGHT_RULE
            + ml_score  * WEIGHT_ML
            + llm_score * WEIGHT_LLM
        )

        # 강한 위험 신호 우선 규칙
        if llm_score >= 90:
            raw = max(weighted, llm_score * 0.85)
        else:
            raw = weighted
    else:
        total_weight = WEIGHT_RULE + WEIGHT_ML
        raw = (
            rule_score * (WEIGHT_RULE / total_weight)
            + ml_score * (WEIGHT_ML   / total_weight)
        )

    return max(0, min(100, round(raw)))


# ── 메인 엔드포인트 ─────────────────────────────────────────────────
@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="문자 메시지 피싱 분석",
    description="하이브리드(규칙+ML+LLM) 방식으로 스미싱 여부를 분석합니다.",
)
@limiter.limit(f"{RATE_LIMIT_PER_MINUTE}/minute")
async def analyze(request: Request, body: AnalyzeRequest) -> AnalyzeResponse:
    """
    POST /analyze

    요청: {"text": "[국민은행] 계좌 정지! 즉시 확인: http://bit.ly/abc"}
    응답: score, level, detected 목록, advice, llm_reason 등
    """
    text = body.text

    # ── 규칙 기반 + ML 병렬 실행 ───────────────────────────────────
    # asyncio.gather 로 두 탐지를 동시 실행 — 응답 속도 개선
    # (순차 실행 대비 ML 처리 시간만큼 단축)
    rule_result, ml_result = await asyncio.gather(
        analyze_rules(text),
        asyncio.to_thread(ml_predict, text),  # 동기 함수를 스레드풀에서 실행
    )

    rule_score: int        = rule_result["rule_score"]
    detected:   list[dict] = rule_result["detected"]
    ml_score:   int        = ml_result["ml_score"]
    ml_prob:    float      = ml_result["ml_probability"]

    # ── 중간 점수: LLM 호출 여부 결정에 사용 ──────────────────────
    intermediate = calculate_final_score(rule_score, ml_score, None)

    # ── LLM 선택적 호출 (40~70점 구간만) ──────────────────────────
    # 비용 절감: 명확한 안전/위험 케이스는 LLM 없이 빠르게 응답
    llm_score:  int | None = None
    llm_reason: str | None = None
    llm_used:   bool       = False

    if LLM_CALL_MIN <= intermediate <= LLM_CALL_MAX:
        llm_result = await analyze_llm(
            text=text,
            rule_score=rule_score,
            detected_items=detected,
            ml_probability=ml_prob,
        )
        llm_score  = llm_result["llm_score"]
        llm_reason = llm_result.get("llm_reason")
        llm_used   = llm_result.get("llm_used", False)

    # ── 최종 점수 + 레벨 + 대처법 ─────────────────────────────────
    final_score = calculate_final_score(rule_score, ml_score, llm_score)
    level  = get_level(final_score)
    advice = get_advice(level, detected)

    return AnalyzeResponse(
        score=final_score,
        level=level,
        rule_score=rule_score,
        ml_score=ml_score,
        ml_probability=ml_prob,
        llm_score=llm_score,
        llm_reason=llm_reason,
        detected=[DetectedItem(**item) for item in detected],
        advice=advice,
        llm_used=llm_used,
    )