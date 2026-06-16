"""
middleware.py
보안 강화 미들웨어 모음

포함 항목:
  1. 요청 로깅 — IP 마스킹, 점수만 저장
  2. 보안 HTTP 헤더 자동 주입
  3. 요청 크기 제한 (대용량 페이로드 공격 방어)
  4. Content-Type 강제 검증

각 기능마다 "왜 필요한지" 주석으로 설명.
"""

import time
import logging
import json
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from config import MAX_TEXT_LENGTH

# ── 로거 설정 ──────────────────────────────────────────────────────
# 보안 이유: print() 대신 logging 모듈 사용
#   - 로그 레벨로 운영/디버그 환경 분리 가능
#   - 나중에 파일 핸들러 추가 시 코드 변경 없음
logger = logging.getLogger("phishing_detector")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


# ── IP 마스킹 유틸 ─────────────────────────────────────────────────
def mask_ip(ip: str) -> str:
    """
    IP 주소의 마지막 두 옥텟을 마스킹한다.

    보안/개인정보 이유:
      IP 주소는 개인을 특정할 수 있는 개인정보임.
      로그에 전체 IP를 남기면 개인정보보호법 위반 가능성.
      마지막 두 자리만 숨겨도 동일 사용자 추적은 불가능해짐.

    예시:
      "192.168.1.100" → "192.168.*.**"
      "::1"           → "::*"  (IPv6 루프백)
    """
    parts = ip.split(".")
    if len(parts) == 4:
        # IPv4: 마지막 두 옥텟 마스킹
        return f"{parts[0]}.{parts[1]}.*.**"
    else:
        # IPv6 또는 기타: 마지막 콜론 뒤 마스킹
        idx = ip.rfind(":")
        return ip[:idx + 1] + "*" if idx != -1 else "*"


# ── 1. 요청/응답 로깅 미들웨어 ────────────────────────────────────
class LoggingMiddleware(BaseHTTPMiddleware):
    """
    모든 요청과 응답을 로깅한다.

    로깅 항목:
      - 마스킹된 IP (마지막 두 옥텟 숨김)
      - HTTP 메서드 + 경로
      - 응답 상태 코드
      - 처리 시간 (ms)
      - /analyze 요청 시: 최종 위험 레벨만 (문자 내용 절대 저장 안 함)

    보안/개인정보 이유:
      문자 내용을 로그에 저장하면:
        1. 개인의 금융 정보가 서버 로그에 남을 수 있음
        2. 로그 파일 탈취 시 2차 피해 발생
        3. 개인정보보호법 위반 가능성
      → 위험 점수와 레벨만 기록해 서비스 품질 모니터링에 필요한
        최소한의 정보만 저장 (데이터 최소화 원칙)
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # 요청 시작 시간
        start = time.perf_counter()

        # IP 마스킹
        client_ip = request.client.host if request.client else "unknown"
        masked_ip = mask_ip(client_ip)

        # 요청 처리
        response = await call_next(request)

        # 처리 시간 계산
        elapsed_ms = round((time.perf_counter() - start) * 1000, 1)

        # 기본 로그 (모든 요청)
        log_msg = (
            f"{masked_ip} | {request.method} {request.url.path} "
            f"| {response.status_code} | {elapsed_ms}ms"
        )

        # /analyze 엔드포인트: 응답 바디에서 레벨만 추출해 추가 로깅
        # 문자 내용(요청 body)은 절대 로깅하지 않음
        if request.url.path == "/analyze" and response.status_code == 200:
            try:
                # 응답 body를 읽고 다시 스트림으로 복원
                body = b""
                async for chunk in response.body_iterator:
                    body += chunk

                data = json.loads(body)
                level = data.get("level", "?")
                score = data.get("score", "?")
                llm_used = "LLM사용" if data.get("llm_used") else "LLM미사용"

                log_msg += f" | {level}({score}점) | {llm_used}"

                # body_iterator를 소비했으므로 새 Response로 복원
                response = Response(
                    content=body,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type,
                )
            except Exception:
                pass  # 로깅 실패가 서비스를 중단시켜서는 안 됨

        logger.info(log_msg)
        return response


# ── 2. 보안 HTTP 헤더 미들웨어 ────────────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    모든 응답에 보안 관련 HTTP 헤더를 자동으로 추가한다.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # X-Content-Type-Options: nosniff
        # 이유: 브라우저가 Content-Type을 무시하고 파일을 실행하는
        #       MIME 스니핑 공격 방어. 예: .jpg 파일을 JS로 실행하는 공격
        response.headers["X-Content-Type-Options"] = "nosniff"

        # X-Frame-Options: DENY
        # 이유: 이 API 응답을 iframe 안에 삽입하는 클릭재킹 공격 방어
        response.headers["X-Frame-Options"] = "DENY"

        # X-XSS-Protection: 1; mode=block
        # 이유: 구형 브라우저에서 반사형 XSS 공격을 브라우저가 직접 차단
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer-Policy: no-referrer
        # 이유: API 요청 시 Referer 헤더로 내부 URL 구조가 외부에 노출되는 것 방지
        response.headers["Referrer-Policy"] = "no-referrer"

        # Content-Security-Policy
        # 이유: API 서버이므로 스크립트/스타일 등 불필요한 리소스 로드 전면 차단
        response.headers["Content-Security-Policy"] = "default-src 'none'"

        # Strict-Transport-Security
        # 이유: HTTPS 강제 — HTTP 다운그레이드를 통한 중간자(MITM) 공격 방어
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

        # 서버 정보 숨기기
        # 이유: 버전 정보 노출 시 공격자가 해당 취약점을 바로 검색해 악용 가능
        response.headers["Server"] = "phishing-detector"

        return response


# ── 3. 요청 크기 제한 미들웨어 ────────────────────────────────────
class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    요청 body 크기를 제한한다.

    보안 이유:
      Content-Length 헤더 없이 매우 큰 body를 전송하는
      슬로우로리스(Slow Loris) 변형 공격이나 메모리 고갈 공격 방어.
      Pydantic의 max_length는 파싱 후 검증이므로
      파싱 자체를 막으려면 미들웨어 레벨에서 크기를 먼저 확인해야 함.

    MAX_BODY_BYTES = MAX_TEXT_LENGTH(1000자) × 4바이트(UTF-8 최대)
                   + JSON 오버헤드 200바이트
    """
    MAX_BODY_BYTES = MAX_TEXT_LENGTH * 4 + 200  # ≈ 4,200 바이트

    async def dispatch(self, request: Request, call_next) -> Response:
        # POST 요청만 크기 체크 (GET 등은 body 없음)
        if request.method == "POST":
            content_length = request.headers.get("content-length")
            if content_length:
                if int(content_length) > self.MAX_BODY_BYTES:
                    # 보안 이유: 크기 초과 즉시 거부 — body를 읽지도 않음
                    return JSONResponse(
                        status_code=413,
                        content={
                            "detail": (
                                f"요청 크기가 너무 큽니다. "
                                f"최대 {self.MAX_BODY_BYTES}바이트까지 허용됩니다."
                            )
                        },
                    )
        return await call_next(request)


# ── 4. Content-Type 검증 미들웨어 ─────────────────────────────────
class ContentTypeMiddleware(BaseHTTPMiddleware):
    """
    POST /analyze 요청의 Content-Type을 강제 검증한다.

    보안 이유:
      Content-Type: application/json 이 아닌 요청
      (예: multipart/form-data, text/plain)으로
      FastAPI 파서를 혼란시키는 Content-Type 스니핑 공격 방어.
      또한 예상치 못한 형식의 데이터가 파이프라인에 진입하는 것을 차단.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method == "POST" and request.url.path == "/analyze":
            ct = request.headers.get("content-type", "")
            if "application/json" not in ct:
                return JSONResponse(
                    status_code=415,
                    content={
                        "detail": (
                            "Content-Type은 application/json 이어야 합니다. "
                            f"받은 값: '{ct}'"
                        )
                    },
                )
        return await call_next(request)