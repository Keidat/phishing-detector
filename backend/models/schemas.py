"""
schemas.py
FastAPI 요청 및 응답 데이터 구조 정의

Pydantic을 사용하는 이유:
  - 타입 기반 자동 검증으로 잘못된 입력을 API 계층에서 차단
  - 입력값 검증을 직접 코딩할 필요가 없어 실수 가능성 감소
"""

from pydantic import BaseModel, Field, field_validator, model_validator
from config import MAX_TEXT_LENGTH


class AnalyzeRequest(BaseModel):
    """클라이언트가 POST /analyze 로 전송하는 요청 body"""
    text: str = Field(
        ...,
        min_length=1,
        max_length=MAX_TEXT_LENGTH,
        description="분석할 문자 메시지 내용"
    )

    @field_validator("text")
    @classmethod
    def sanitize_and_validate_text(cls, v: str) -> str:
        """
        입력 텍스트 위생 처리 + 공백 전용 입력 차단

        보안 이유:
          1. strip() — 앞뒤 공백 제거
          2. Null Byte 제거 — \x00 으로 파서를 혼란시키는 인젝션 방어
          3. 공백 전용 입력 차단 —
             "   " 같은 입력은 strip() 후 빈 문자열이 되어
             탐지 의미가 없으며, min_length=1 을 우회할 수 있음
             (Pydantic이 validator 실행 전에 길이 검사를 하기 때문)
             → validator 안에서 strip 후 길이를 다시 확인해 차단
        """
        # 1. Null Byte Injection 방어
        v = v.replace("\x00", "")
        # 2. 앞뒤 공백 제거
        v = v.strip()
        # 3. 공백만으로 이루어진 입력 차단
        if not v:
            raise ValueError("공백만으로 이루어진 입력은 허용되지 않습니다.")
        return v


class DetectedItem(BaseModel):
    """개별 탐지 항목"""
    type: str    # "URL" | "short_url" | "keyword" | "personal_info"
    value: str   # 탐지된 실제 값
    reason: str  # 탐지 이유 설명


class AnalyzeResponse(BaseModel):
    """POST /analyze 응답"""
    score: int                      # 최종 종합 점수 0~100
    level: str                      # "안전" | "주의" | "위험"
    rule_score: int                 # 규칙 기반 점수
    ml_score: int                   # ML 모델 점수
    ml_probability: float           # ML 피싱 확률 0.0~1.0
    llm_score: int | None = None    # LLM 점수 (호출된 경우만)
    llm_reason: str | None = None   # LLM 자연어 설명
    detected: list[DetectedItem]    # 탐지된 항목 목록
    advice: str                     # 대처법 안내 문구
    llm_used: bool = False          # LLM 호출 여부 (디버그용)
    llm_engine: str | None = None   # [신규] 최종 판단에 사용된 LLM 엔진 ("groq" | "gemini" | None)