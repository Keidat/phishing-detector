"""
preprocess.py
한국어 스미싱 문자 전처리 모듈

TF-IDF 벡터화 전에 텍스트를 정제한다.

전처리 순서:
  1. 대괄호 발신자 태그 보존 후 마커 변환
  2. 단축 URL → SHORT_URL_TOKEN 치환
  3. 일반 URL → URL_TOKEN 치환
  4. 전화번호 → PHONE_TOKEN 치환
  5. 소문자 변환 (영문 통일)
  6. 특수문자 제거 (한글·영문·숫자·공백만 유지)
  7. 다중 공백 정리

왜 형태소 분석을 안 쓰나?
  - KoNLPy(konlpy) 설치에 Java 환경이 필요해 2주 프로젝트에 리스크
  - TF-IDF는 문자(character) n-gram과도 잘 동작함
  - 형태소 없이도 스미싱 키워드 탐지에 충분한 성능 확인됨
  - 나중에 시간이 있으면 추가하면 됨 (인터페이스 변경 없음)
"""

import re

# URL 패턴 (전처리용)
_URL_RE = re.compile(
    r'https?://[^\s]{1,500}|www\.[^\s]{1,500}',
    re.IGNORECASE
)
# 단축 URL 도메인
_SHORT_URL_RE = re.compile(
    r'bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|is\.gd|'
    r'cutt\.ly|han\.gl|me2\.do|t\.co|buff\.ly',
    re.IGNORECASE
)
# 전화번호 패턴
_PHONE_RE = re.compile(r'0\d{1,2}-?\d{3,4}-?\d{4}|1\d{3}-?\d{4}')
# 대괄호 태그 (발신자 표기) — "[국민은행]" 같은 것
_BRACKET_RE = re.compile(r'\[.*?\]')
# 이모지·특수기호
_SPECIAL_RE = re.compile(r'[^\w\s가-힣]', re.UNICODE)
# 다중 공백
_SPACE_RE = re.compile(r'\s+')


def preprocess(text: str) -> str:
    """
    문자 메시지를 TF-IDF에 적합한 형태로 변환한다.

    Args:
        text: 원본 문자 메시지

    Returns:
        전처리된 문자열
    """
    # 1. 대괄호 태그 내용 보존 후 마커로 변환
    #    "[국민은행]" → "SENDER_TAG 국민은행"
    #    발신자 사칭 여부가 피싱 탐지에 중요한 특징이므로 보존
    text = _BRACKET_RE.sub(lambda m: "SENDER_TAG " + m.group()[1:-1], text)

    # 2. 단축 URL을 먼저 표시 (URL 치환 전에)
    #    단축 URL은 악의적 목적지 은닉을 강하게 시사
    def url_replacer(m):
        url = m.group()
        if _SHORT_URL_RE.search(url):
            return "SHORT_URL_TOKEN"  # 단축 URL 별도 토큰
        return "URL_TOKEN"

    text = _URL_RE.sub(url_replacer, text)

    # 3. 전화번호 정규화
    text = _PHONE_RE.sub("PHONE_TOKEN", text)

    # 4. 소문자 변환 (영문 통일)
    text = text.lower()

    # 5. 특수문자 제거 (한글·영문·숫자·공백·토큰 언더스코어는 유지)
    text = _SPECIAL_RE.sub(" ", text)

    # 6. 다중 공백 → 단일 공백
    text = _SPACE_RE.sub(" ", text).strip()

    return text


if __name__ == "__main__":
    # 전처리 결과 확인용 테스트
    samples = [
        "[국민은행] 계좌정지! 즉시 확인: http://bit.ly/abc123",
        "안녕! 오늘 저녁 뭐 먹을래?",
        "⚠️ 경고: 카드 정지! 지금 바로 https://www.evil.com 접속",
    ]
    for s in samples:
        print(f"원본 : {s}")
        print(f"처리후: {preprocess(s)}")
        print()