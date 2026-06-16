"""
ml_model.py
학습된 스미싱 분류 모델 로드 및 예측 모듈

사용 방법:
  1. 먼저 ml_training/train.py 를 실행해 model.pkl 생성
  2. FastAPI 시작 시 load_model() 호출 (앱 전역에 1회만)
  3. predict() 로 피싱 확률 반환

설계 원칙:
  - 모델은 앱 시작 시 메모리에 1번만 로드 (요청마다 파일 읽기 금지)
  - 모델 파일 없으면 명확한 오류 메시지 출력
  - predict()는 동기 함수 — sklearn은 비동기 미지원이므로 그대로 사용
"""

import os
import sys
import joblib
import numpy as np
from sklearn.pipeline import Pipeline

# 전처리 모듈 경로 추가
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../ml_training"))
from preprocess import preprocess

# ── 모델 경로 ──────────────────────────────────────────────────────
MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "../ml_training/model.pkl"
)

# 전역 모델 객체 (앱 시작 시 1회 로드, 이후 재사용)
_model: Pipeline | None = None


# ── 모델 로드 ──────────────────────────────────────────────────────
def load_model() -> bool:
    """
    model.pkl 을 메모리에 로드한다.
    FastAPI lifespan 또는 startup 이벤트에서 1회 호출.

    Returns:
        True: 로드 성공
        False: 파일 없음 (ML 기능 비활성화)
    """
    global _model

    abs_path = os.path.abspath(MODEL_PATH)
    if not os.path.exists(abs_path):
        print(f"⚠️  ML 모델 파일 없음: {abs_path}")
        print("   → ml_training/train.py 를 먼저 실행하세요")
        print("   → ML 탐지 없이 규칙 기반 + LLM 으로만 동작합니다")
        return False

    _model = joblib.load(abs_path)
    print(f"✅ ML 모델 로드 완료: {abs_path}")
    return True


def is_model_loaded() -> bool:
    """모델이 로드된 상태인지 확인"""
    return _model is not None


# ── 예측 함수 ──────────────────────────────────────────────────────
def predict(text: str) -> dict:
    """
    문자 메시지의 스미싱 확률을 반환한다.

    Args:
        text: 원본 문자 메시지 (전처리는 내부에서 처리)

    Returns:
        {
            "ml_score": 85,          # 0~100 정수 점수
            "ml_probability": 0.85   # 0.0~1.0 확률값
        }
        모델 미로드 시: ml_score=0, ml_probability=0.0 (graceful degradation)
    """
    # 모델 없으면 0점 반환 (서비스 중단 없이 계속 동작)
    if _model is None:
        return {"ml_score": 0, "ml_probability": 0.0}

    # 전처리 적용 후 예측
    processed = preprocess(text)

    # predict_proba: [[정상 확률, 피싱 확률]] 형태로 반환
    proba = _model.predict_proba([processed])[0]
    phishing_prob = float(proba[1])

    # 확률을 0~100 점수로 변환
    score = round(phishing_prob * 100)

    return {
        "ml_score": score,
        "ml_probability": round(phishing_prob, 4),
    }