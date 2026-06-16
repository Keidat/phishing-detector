"""
llm_analyzer.py
Google Gemini API 연동 모듈

역할:
  - 규칙+ML 합산 점수가 40~70점(애매한 구간)일 때만 호출
  - Gemini에게 문자 내용 + 탐지 결과를 주고 피싱 여부 최종 판단
  - "왜 피싱인지" 한국어 자연어 설명 생성

비용 절감 설계:
  - 40점 미만 → 안전 확실 → LLM 호출 안 함
  - 70점 초과 → 위험 확실 → LLM 호출 안 함
  - 40~70점만 → LLM 호출

보안 설계:
  - API 키는 환경변수 GEMINI_API_KEY 로만 관리
  - LLM 응답 JSON 파싱 실패 시 graceful degradation
  - 타임아웃 20초
  - 프롬프트 인젝션 방어: 사용자 입력을 XML 태그로 격리
"""

import json
import re
import os
import asyncio
import google.generativeai as genai
from google.generativeai.types import GenerationConfig

from config import GEMINI_API_KEY, LLM_MODEL, LLM_MAX_TOKENS

# ── Gemini 클라이언트 초기화 ────────────────────────────────────────
# 모듈 로드 시 1회만 설정 (매 요청마다 초기화하면 오버헤드 발생)
_model = None

def get_model():
    """
    Gemini 모델 싱글톤 반환.
    API 키가 없으면 None 반환 (LLM 기능 비활성화).
    """
    global _model
    if not GEMINI_API_KEY:
        return None
    if _model is None:
        # 보안 이유: API 키를 환경변수에서만 읽어 코드에 노출하지 않음
        genai.configure(api_key=GEMINI_API_KEY)
        _model = genai.GenerativeModel(
            model_name=LLM_MODEL,
            generation_config=GenerationConfig(
                max_output_tokens=LLM_MAX_TOKENS,
                temperature=0.1,  # 낮은 temperature: 일관된 JSON 응답 유도
            ),
            system_instruction=(
                "당신은 한국 스미싱 탐지 전문가입니다. "
                "요청받은 JSON 형식으로만 응답하세요. "
                "절대로 JSON 외의 텍스트를 포함하지 마세요."
            ),
        )
    return _model


# ── 프롬프트 구성 ───────────────────────────────────────────────────
def build_prompt(
    text: str,
    rule_score: int,
    detected_items: list[dict],
    ml_probability: float,
) -> str:
    """
    Gemini에게 보낼 분석 요청 프롬프트를 구성한다.

    프롬프트 인젝션 방어 전략:
      - 사용자 입력(text)을 XML 태그로 명확히 감싸서
        모델이 "데이터"와 "지시문"을 혼동하지 않도록 함
      - JSON 응답 형식을 강제해 프롬프트 탈출 시도를 무력화
    """
    detected_summary = "\n".join(
        f"  - [{item['type']}] {item['value'][:50]}: {item['reason']}"
        for item in detected_items[:10]
    ) or "  - 없음"

    return f"""당신은 한국 사이버보안 전문가입니다. 아래 문자 메시지가 스미싱(피싱 문자)인지 분석해주세요.

## 분석 대상 문자 메시지
<message>
{text[:800]}
</message>

## 사전 분석 결과
- 규칙 기반 점수: {rule_score}/100
- ML 모델 피싱 확률: {ml_probability:.1%}
- 탐지된 항목:
{detected_summary}

## 요청
위 문자가 스미싱(피싱)인지 종합적으로 판단하고, 반드시 아래 JSON 형식으로만 응답하세요.
다른 텍스트, 설명, 마크다운은 절대 포함하지 마세요.

{{"score": 0~100 사이 정수, "reason": "판단 근거를 한국어로 1~2문장, 80자 이내로 간결하게 설명"}}

판단 기준:
- 금융기관/정부기관 사칭 여부
- 개인정보/금융정보 요구 여부
- 심리적 긴급성 조성 여부
- URL 은닉 또는 단축 URL 사용 여부
- 문체의 자연스러움 (어색한 표현 = 위험 신호)"""


# ── JSON 파싱 (3단계 fallback) ──────────────────────────────────────
def parse_llm_response(raw: str) -> dict | None:
    """
    LLM 응답에서 JSON을 추출하고 파싱한다.
    1차: 직접 파싱
    2차: 마크다운 코드블록 안의 JSON
    3차: 텍스트 중 JSON 객체 추출
    """
    # 1차: 직접 JSON 파싱
    try:
        data = json.loads(raw.strip())
        if "score" in data and "reason" in data:
            return data
    except json.JSONDecodeError:
        pass

    # 2차: 마크다운 코드블록
    code_block = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if code_block:
        try:
            data = json.loads(code_block.group(1))
            if "score" in data and "reason" in data:
                return data
        except json.JSONDecodeError:
            pass

    # 3차: 텍스트 중간의 JSON 객체 추출
    json_match = re.search(r"\{[^{}]*\"score\"[^{}]*\"reason\"[^{}]*\}", raw, re.DOTALL)
    if json_match:
        try:
            data = json.loads(json_match.group())
            if "score" in data and "reason" in data:
                return data
        except json.JSONDecodeError:
            pass

    # 4차: 잘린 JSON 복구 시도
    # score는 찾았지만 reason이 닫히지 않은 경우, score만이라도 살린다
    score_match = re.search(r'"score"\s*:\s*(\d+)', raw)
    reason_match = re.search(r'"reason"\s*:\s*"([^"]*)', raw)
    if score_match:
        return {
            "score": int(score_match.group(1)),
            "reason": (reason_match.group(1) if reason_match else "응답이 일부만 수신되었습니다.") + " (응답 일부 누락)",
        }

    return None


# ── 메인 LLM 분석 함수 ──────────────────────────────────────────────
async def analyze_llm(
    text: str,
    rule_score: int,
    detected_items: list[dict],
    ml_probability: float,
) -> dict:
    """
    Gemini API를 호출해 최종 피싱 판단 및 자연어 설명을 반환한다.

    Returns:
        {"llm_score": 90, "llm_reason": "...", "llm_used": True}
        실패 시: {"llm_score": None, "llm_reason": None, "llm_used": False}
    """
    model = get_model()

    if model is None:
        # API 키 없으면 LLM 기능 비활성화 (서비스는 계속 동작)
        return {"llm_score": None, "llm_reason": None, "llm_used": False}

    prompt = build_prompt(text, rule_score, detected_items, ml_probability)

    try:
        # Gemini는 동기 API이므로 스레드풀에서 실행 (FastAPI 비동기 블로킹 방지)
        # 보안 이유: 타임아웃 20초 — LLM 지연으로 인한 서비스 블로킹 방지
        response = await asyncio.wait_for(
            asyncio.to_thread(model.generate_content, prompt),
            timeout=20.0
        )

        raw_text = response.text
        parsed = parse_llm_response(raw_text)

        if parsed is None:
            print(f"⚠️  LLM 응답 파싱 실패. 원본: {raw_text[:200]}")
            return {
                "llm_score": None,
                "llm_reason": "LLM 분석 결과를 파싱하지 못했습니다.",
                "llm_used": True,
            }

        # 점수 범위 강제 (0~100)
        score = max(0, min(100, int(parsed["score"])))
        reason = str(parsed["reason"])[:500]

        return {"llm_score": score, "llm_reason": reason, "llm_used": True}

    except asyncio.TimeoutError:
        print("⚠️  Gemini API 타임아웃 (20초 초과)")
        return {"llm_score": None, "llm_reason": None, "llm_used": False}

    except Exception as e:
        print(f"⚠️  Gemini API 오류: {type(e).__name__}: {e}")
        return {"llm_score": None, "llm_reason": None, "llm_used": False}