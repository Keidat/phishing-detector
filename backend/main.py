"""
main.py
FastAPI 앱 진입점 — 보안 강화 최종 버전

등록 미들웨어 (실행 순서: 아래→위, 등록 순서와 반대):
  1. RequestSizeLimitMiddleware — 대용량 페이로드 공격 방어
  2. ContentTypeMiddleware     — Content-Type 스니핑 방어
  3. SecurityHeadersMiddleware — 보안 HTTP 헤더 자동 주입
  4. LoggingMiddleware         — IP 마스킹 로그, 문자 내용 비저장
  5. CORSMiddleware            — 허가된 출처만 접근 허용

실행 방법:
  uvicorn main:app --reload --port 8000
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from config import ALLOWED_ORIGINS
from detectors.ml_model import load_model
from database.db_loader import load_rules_from_db  # DB 규칙 캐시 로더 추가
from security.middleware import (
    LoggingMiddleware,
    SecurityHeadersMiddleware,
    RequestSizeLimitMiddleware,
    ContentTypeMiddleware,
)


# ── 앱 시작/종료 이벤트 ────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    시작 시:
      1. ML 모델 메모리 로드
      2. DB 규칙 데이터 로드 및 캐싱 (키워드/도메인/패턴)

    보안 이유:
      - 요청마다 파일·DB를 읽으면 디스크 I/O 과부하 → DoS 취약
      - 서버 시작 시 한 번만 읽어 메모리에 캐싱하여 성능과 안정성 확보
    """
    # ML 모델 로드 (기존 동작 유지)
    load_model()

    # DB에서 규칙 데이터 로드 및 모듈 캐시에 저장
    # DB 연결 실패 시 db_loader가 빈 캐시로 graceful하게 처리하므로
    # 서버 시작이 중단되지 않음
    load_rules_from_db()

    yield


# ── Rate Limiter 초기화 ────────────────────────────────────────────
# 보안 이유: IP당 분당 요청 수를 제한해 무차별 대입 및 API 남용 방어
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="피싱 문자 탐지 API",
    description="하이브리드(규칙+ML+LLM) 방식의 실시간 스미싱 탐지 서비스",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
)

# Rate limit 초과 → 429 응답
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── 미들웨어 등록 ──────────────────────────────────────────────────
# 주의: FastAPI 미들웨어는 등록 역순으로 실행됨
#       즉 마지막에 추가한 것이 요청을 가장 먼저 받음

# 4. 로깅 (가장 바깥 — 모든 요청/응답 기록)
app.add_middleware(LoggingMiddleware)

# 3. 보안 헤더 (모든 응답에 헤더 삽입)
app.add_middleware(SecurityHeadersMiddleware)

# 2. Content-Type 검증 (POST /analyze 만 적용)
app.add_middleware(ContentTypeMiddleware)

# 1. 요청 크기 제한 (가장 안쪽 — 파싱 전 크기 먼저 차단)
app.add_middleware(RequestSizeLimitMiddleware)

# CORS (별도 미들웨어로 관리)
# 보안 이유: 허용된 출처에서만 API 요청 수락 → CSRF 방어
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["Content-Type", "ngrok-skip-browser-warning"],
)

# ── 라우터 등록 ────────────────────────────────────────────────────
from api.analyze import router as analyze_router
app.include_router(analyze_router)


# ── 헬스체크 ───────────────────────────────────────────────────────
@app.get("/health")
async def health_check():
    """서버 상태 + ML 모델 로드 여부 + DB 규칙 로드 여부 확인"""
    from detectors.ml_model import is_model_loaded
    from database.db_loader import get_cached_rules

    rules = get_cached_rules()
    return {
        "status": "ok",
        "ml_model_loaded": is_model_loaded(),
        # DB 규칙 로드 여부: 각 항목 건수로 확인
        "db_rules_loaded": {
            "urgency_keywords":       len(rules["urgency_keywords"]),
            "short_url_domains":      len(rules["short_url_domains"]),
            "personal_info_patterns": len(rules["personal_info_patterns"]),
        },
    }


# ── 프론트엔드 정적 파일 서빙 ────────────────────────────────────
# ngrok 터널 1개로 백엔드+프론트엔드를 함께 제공하기 위한 설정
# (무료 ngrok은 터널을 1개만 열 수 있으므로 이렇게 통합)
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")