"""
config.py
환경변수 로드 및 전역 설정 관리

보안 이유:
  - API 키를 코드에 하드코딩하지 않고 .env 파일로 분리
  - .env 파일은 .gitignore에 반드시 추가 (GitHub 유출 방지)
  - 필수 환경변수 누락 시 서버 시작 단계에서 명시적 오류 출력
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ── API 키 ─────────────────────────────────────
VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")  # Anthropic → Gemini로 변경

# ── 서버 설정 ───────────────────────────────────
ALLOWED_ORIGINS: list[str] = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:5500"
).split(",")

# ── Rate Limiting ───────────────────────────────
RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "10"))

# ── 입력 제한 ───────────────────────────────────
MAX_TEXT_LENGTH: int = 1000

# ── LLM 설정 ───────────────────────────────────
# gemini-1.5-flash: 무료 티어 지원, 빠른 응답 속도
LLM_MODEL: str = "gemini-2.5-flash"
LLM_MAX_TOKENS: int = 1024

# ── 점수 임계값 ─────────────────────────────────
# 40~70점 구간에서만 LLM 호출 (비용 및 속도 최적화)
LLM_CALL_MIN: int = 40
LLM_CALL_MAX: int = 70

# ── 가중치 ─────────────────────────────────────
WEIGHT_RULE: float = 0.30
WEIGHT_ML: float   = 0.40
WEIGHT_LLM: float  = 0.30