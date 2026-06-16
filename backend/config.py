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

# 프로젝트 루트의 .env 파일 로드
load_dotenv()

# ── API 키 ─────────────────────────────────────
# 환경변수에서 읽기, 없으면 빈 문자열 (해당 기능 비활성화)
VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")

# ── 서버 설정 ───────────────────────────────────
ALLOWED_ORIGINS: list[str] = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:5500"  # 개발 기본값
).split(",")

# ── Rate Limiting 설정 ──────────────────────────
RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "10"))

# ── 입력 제한 ───────────────────────────────────
MAX_TEXT_LENGTH: int = 1000  # 문자 메시지 최대 길이

# ── LLM 설정 ───────────────────────────────────
LLM_MODEL: str = "claude-sonnet-4-6"
LLM_MAX_TOKENS: int = 500

# ── 점수 임계값 ─────────────────────────────────
# 이 구간(40~70)에서만 LLM API를 호출해 비용과 속도를 최적화
LLM_CALL_MIN: int = 40
LLM_CALL_MAX: int = 70

# ── 가중치 ─────────────────────────────────────
WEIGHT_RULE: float = 0.30   # 규칙 기반 30%
WEIGHT_ML: float = 0.40     # ML 모델  40%
WEIGHT_LLM: float = 0.30    # LLM      30%