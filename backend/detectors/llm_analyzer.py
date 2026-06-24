"""
llm_analyzer.py
Groq(1차) + Gemini(2차) 하이브리드 LLM 분석 모듈

역할:
  - Groq API (llama3): 항상 호출, 1차 피싱 여부 판단
    → API 제한이 넉넉해 키워드/URL 없는 문자도 잡을 수 있음
  - Gemini API: Groq 점수가 60점 이상일 때만 호출, 최종 확인 + 자연어 설명 생성
    → API 호출 최소화로 무료 한도 절약

보안 설계:
  - API 키는 환경변수로만 관리
  - 프롬프트 인젝션 방어: 사용자 입력을 XML 태그로 격리
  - 타임아웃 20초
  - LLM 응답 JSON 파싱 실패 시 graceful degradation
"""

import json
import re
import os
import asyncio
import httpx
import google.generativeai as genai
from google.generativeai.types import GenerationConfig

from config import (
    GEMINI_API_KEY, LLM_MODEL, LLM_MAX_TOKENS,
    GROQ_API_KEY, GROQ_MODEL, GROQ_MAX_TOKENS,
)

# ── Groq 호출 점수 임계값 ────────────────────────────────────────────
# Groq 점수가 이 값 이상이면 Gemini를 추가로 호출
GROQ_TO_GEMINI_THRESHOLD = 60

# ── Gemini 클라이언트 초기화 ────────────────────────────────────────
_gemini_model = None

def get_gemini_model():
    """Gemini 모델 싱글톤 반환. API 키 없으면 None."""
    global _gemini_model
    if not GEMINI_API_KEY:
        return None
    if _gemini_model is None:
        genai.configure(api_key=GEMINI_API_KEY)
        _gemini_model = genai.GenerativeModel(
            model_name=LLM_MODEL,
            generation_config=GenerationConfig(
                max_output_tokens=LLM_MAX_TOKENS,
                temperature=0.1,
            ),
            system_instruction=(
                "당신은 한국 스미싱 탐지 전문가입니다. "
                "요청받은 JSON 형식으로만 응답하세요. "
                "절대로 JSON 외의 텍스트를 포함하지 마세요."
            ),
        )
    return _gemini_model


# ── 공통 프롬프트 구성 ──────────────────────────────────────────────
def build_prompt(
    text: str,
    rule_score: int,
    detected_items: list[dict],
    ml_probability: float,
) -> str:
    """
    Groq/Gemini 공통으로 사용하는 분석 요청 프롬프트.
    프롬프트 인젝션 방어: 사용자 입력을 XML 태그로 격리
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

## 중요: 오탐 방지 원칙
- URL이 존재한다는 사실 자체는 위험 신호가 아닙니다.
- 비속어, 밈, 인터넷 은어, 장난 표현은 "이상함"이지 "위험함"이 아닙니다.
- 아래의 명확한 위험 신호가 하나도 없다면 score는 20점 이하로 평가하세요.

## 명확한 위험 신호 (이 중 하나 이상이 있어야 위험으로 판단)
1. 금융기관, 정부기관, 택배사 등 공식 기관을 사칭하는 표현
2. 금전, 개인정보(주민번호, 카드번호, 비밀번호, 계좌번호)를 요구
3. "즉시", "지금 바로", "계좌 정지" 등 심리적 긴급성/공포를 조성하는 표현
4. 단축 URL이나 의심스러운 방식으로 목적지를 숨기는 URL
5. 전화나 클릭을 유도하면서 동시에 금전적 피해와 연결될 수 있는 맥락

위 신호가 없으면 낮은 점수를 주세요. 판단이 애매하면 "확실한 근거 부족"으로 처리하세요."""


# ── JSON 파싱 (4단계 fallback) ──────────────────────────────────────
def parse_llm_response(raw: str) -> dict | None:
    """LLM 응답에서 JSON을 추출하고 파싱한다."""
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

    # 3차: 텍스트 중 JSON 객체 추출
    json_match = re.search(r"\{[^{}]*\"score\"[^{}]*\"reason\"[^{}]*\}", raw, re.DOTALL)
    if json_match:
        try:
            data = json.loads(json_match.group())
            if "score" in data and "reason" in data:
                return data
        except json.JSONDecodeError:
            pass

    # 4차: 잘린 JSON 복구
    score_match = re.search(r'"score"\s*:\s*(\d+)', raw)
    reason_match = re.search(r'"reason"\s*:\s*"([^"]*)', raw)
    if score_match:
        return {
            "score": int(score_match.group(1)),
            "reason": (reason_match.group(1) if reason_match else "응답이 일부만 수신되었습니다.") + " (응답 일부 누락)",
        }

    return None


# ── Groq API 호출 (1차 분석) ────────────────────────────────────────
async def analyze_groq(
    text: str,
    rule_score: int,
    detected_items: list[dict],
    ml_probability: float,
) -> dict:
    """
    Groq API(llama3)로 1차 피싱 판단을 수행한다.
    API 제한이 넉넉해 모든 문자에 대해 호출 가능.

    Returns:
        {"groq_score": 75, "groq_used": True}
        실패 시: {"groq_score": None, "groq_used": False}
    """
    if not GROQ_API_KEY:
        return {"groq_score": None, "groq_used": False}

    prompt = build_prompt(text, rule_score, detected_items, ml_probability)

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": GROQ_MODEL,
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "당신은 한국 스미싱 탐지 전문가입니다. "
                                "요청받은 JSON 형식으로만 응답하세요. "
                                "절대로 JSON 외의 텍스트를 포함하지 마세요."
                            )
                        },
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": GROQ_MAX_TOKENS,
                    "temperature": 0.1,
                }
            )

            if response.status_code != 200:
                print(f"⚠️  Groq API 오류: {response.status_code} {response.text[:200]}")
                return {"groq_score": None, "groq_used": False}

            data = response.json()
            raw_text = data["choices"][0]["message"]["content"]
            parsed = parse_llm_response(raw_text)

            if parsed is None:
                print(f"⚠️  Groq 응답 파싱 실패. 원본: {raw_text[:200]}")
                return {"groq_score": None, "groq_used": True}

            score = max(0, min(100, int(parsed["score"])))
            return {"groq_score": score, "groq_used": True}

    except asyncio.TimeoutError:
        print("⚠️  Groq API 타임아웃 (20초 초과)")
        return {"groq_score": None, "groq_used": False}

    except Exception as e:
        print(f"⚠️  Groq API 오류: {type(e).__name__}: {e}")
        return {"groq_score": None, "groq_used": False}


# ── Gemini API 호출 (2차 확인) ──────────────────────────────────────
async def analyze_gemini(
    text: str,
    rule_score: int,
    detected_items: list[dict],
    ml_probability: float,
) -> dict:
    """
    Gemini API로 2차 최종 확인 및 자연어 설명을 생성한다.
    Groq 점수가 60점 이상일 때만 호출되어 API 한도를 절약한다.

    Returns:
        {"llm_score": 90, "llm_reason": "...", "llm_used": True, "llm_engine": "gemini"}
        실패 시: {"llm_score": None, "llm_reason": None, "llm_used": False, "llm_engine": None}
    """
    model = get_gemini_model()

    if model is None:
        return {"llm_score": None, "llm_reason": None, "llm_used": False, "llm_engine": None}

    prompt = build_prompt(text, rule_score, detected_items, ml_probability)

    try:
        response = await asyncio.wait_for(
            asyncio.to_thread(model.generate_content, prompt),
            timeout=20.0
        )

        raw_text = response.text
        parsed = parse_llm_response(raw_text)

        if parsed is None:
            print(f"⚠️  Gemini 응답 파싱 실패. 원본: {raw_text[:200]}")
            return {
                "llm_score": None,
                "llm_reason": "LLM 분석 결과를 파싱하지 못했습니다.",
                "llm_used": True,
                "llm_engine": "gemini",  # [신규] 파싱 실패여도 Gemini까지 호출된 사실은 기록
            }

        score = max(0, min(100, int(parsed["score"])))
        reason = str(parsed["reason"])[:500]
        return {
            "llm_score": score,
            "llm_reason": reason,
            "llm_used": True,
            "llm_engine": "gemini",  # [신규] Gemini가 최종 판단
        }

    except asyncio.TimeoutError:
        print("⚠️  Gemini API 타임아웃 (20초 초과)")
        return {"llm_score": None, "llm_reason": None, "llm_used": False, "llm_engine": None}

    except Exception as e:
        print(f"⚠️  Gemini API 오류: {type(e).__name__}: {e}")
        return {"llm_score": None, "llm_reason": None, "llm_used": False, "llm_engine": None}


# ── 메인 LLM 분석 함수 (기존 인터페이스 유지) ───────────────────────
async def analyze_llm(
    text: str,
    rule_score: int,
    detected_items: list[dict],
    ml_probability: float,
) -> dict:
    """
    Groq(1차) + Gemini(2차) 하이브리드 분석을 수행한다.

    흐름:
      1. Groq로 1차 분석 (항상 호출)
      2. Groq 점수 60점 이상 → Gemini로 2차 확인 + 자연어 설명
      3. Groq 점수 60점 미만 → Gemini 호출 생략, Groq 점수만 반환

    반환값에 llm_engine 필드 추가:
      - "gemini" : Gemini까지 호출되어 최종 판단
      - "groq"   : Groq만 사용하여 최종 판단
      - None     : 모든 LLM 호출 실패

    Returns:
        {"llm_score": 90, "llm_reason": "...", "llm_used": True, "llm_engine": "gemini"}
    """
    # ── 1차: Groq 분석 ─────────────────────────────
    groq_result = await analyze_groq(text, rule_score, detected_items, ml_probability)
    groq_score = groq_result.get("groq_score")

    # ── 2차: Groq 점수 기반 Gemini 호출 결정 ────────
    if groq_score is not None and groq_score >= GROQ_TO_GEMINI_THRESHOLD:
        # Groq가 위험하다고 판단 → Gemini로 최종 확인 + 자연어 설명
        print(f"[LLM] Groq 점수 {groq_score}점 → Gemini 2차 호출")
        gemini_result = await analyze_gemini(text, rule_score, detected_items, ml_probability)
        return gemini_result  # llm_engine: "gemini" 포함

    elif groq_score is not None:
        # Groq가 안전하다고 판단 → Gemini 호출 생략, Groq 점수만 반환
        print(f"[LLM] Groq 점수 {groq_score}점 → Gemini 호출 생략")
        return {
            "llm_score": groq_score,
            "llm_reason": None,      # 자연어 설명 없음 (안전으로 판단)
            "llm_used": True,
            "llm_engine": "groq",    # [신규] Groq만 사용하여 최종 판단
        }

    else:
        # Groq 호출 실패 → Gemini로 대체
        print("[LLM] Groq 실패 → Gemini로 대체 호출")
        gemini_result = await analyze_gemini(text, rule_score, detected_items, ml_probability)
        return gemini_result  # llm_engine: "gemini" 또는 None 포함