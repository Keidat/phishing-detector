"""
train.py
스미싱 분류 모델 학습 스크립트

실행 방법 (배포 전 1회):
  cd backend/ml_training
  python train.py

출력:
  model.pkl   — 학습된 Pipeline (전처리 + 분류기)
  report.txt  — 성능 보고서

모델 선택 이유:
  Logistic Regression
  - 2주 내 구현 가능, 학습 속도 빠름
  - 스팸/피싱 분류처럼 선형 경계가 뚜렷한 문제에 강함
  - predict_proba()로 확률값 바로 출력 가능
  - Random Forest 대비 설명 가능성이 높음 (발표에 유리)

  Random Forest는 주석으로 대안 코드를 남겨둠.
"""

import os
import sys
import json
import joblib
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, accuracy_score
)

# 상위 디렉토리에서 preprocess 임포트
sys.path.insert(0, os.path.dirname(__file__))
from preprocess import preprocess

# ── 경로 설정 ──────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(__file__)
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
MODEL_OUTPUT_PATH = os.path.join(BASE_DIR, "model.pkl")
REPORT_PATH = os.path.join(BASE_DIR, "report.txt")

# AI Hub 등 외부 데이터셋을 사용할 경우 이 경로를 변경
CSV_PATH = os.path.join(DATASET_DIR, "smishing_ko.csv")


def load_dataset(csv_path: str) -> tuple[list[str], list[int]]:
    """
    CSV 데이터셋을 로드하고 전처리를 적용한다.

    CSV 형식:
      label,text
      1,"[국민은행] 즉시 확인..."
      0,"안녕! 오늘 점심..."

    외부 데이터셋 연동:
      AI Hub 데이터의 경우 컬럼명이 다를 수 있음.
      아래 rename 부분을 데이터셋에 맞게 수정할 것.
    """
    df = pd.read_csv(csv_path, encoding="utf-8")

    # 컬럼명 표준화 (외부 데이터셋 대응)
    # AI Hub: "문장", "레이블" 형식일 수 있음
    if "문장" in df.columns:
        df = df.rename(columns={"문장": "text", "레이블": "label"})
    if "message" in df.columns:
        df = df.rename(columns={"message": "text"})

    # 결측값 제거
    df = df.dropna(subset=["text", "label"])
    df["label"] = df["label"].astype(int)

    # 전처리 적용
    print(f"📂 데이터 로드: {len(df)}건")
    texts = [preprocess(t) for t in df["text"].tolist()]
    labels = df["label"].tolist()

    smishing = sum(labels)
    normal = len(labels) - smishing
    print(f"   스미싱: {smishing}건 | 정상: {normal}건")
    return texts, labels


def build_pipeline() -> Pipeline:
    """
    TF-IDF 벡터화 + Logistic Regression 파이프라인 구성

    TF-IDF 파라미터 설명:
      analyzer='char_wb' — 문자 단위 n-gram
                           형태소 분석기 없이도 한국어 부분 일치 탐지 가능
                           "즉시"와 "즉시입금" 등 변형도 잡아냄
      ngram_range=(2,4)  — 2~4글자 조합 사용
      max_features=30000 — 메모리 제한 (너무 많으면 느려짐)
      sublinear_tf=True  — TF에 로그 스케일 적용 (빈도 폭발 억제)
    """
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char_wb",      # 문자 n-gram (형태소 분석기 불필요)
            ngram_range=(2, 4),      # 2~4글자 조합
            max_features=30000,      # 특징 수 상한
            sublinear_tf=True,       # 로그 TF 스케일
            min_df=1,                # 최소 등장 횟수 (소규모 데이터셋 대응)
        )),
        ("clf", LogisticRegression(
            C=1.0,                   # 정규화 강도 (클수록 과적합 위험)
            class_weight="balanced", # 클래스 불균형 자동 보정
            max_iter=1000,           # 수렴 보장
            random_state=42,
            solver="lbfgs",          # 소규모 데이터에 적합한 솔버
        )),
        # ── Random Forest 대안 (주석 해제해서 사용) ──────────────
        # ("clf", RandomForestClassifier(
        #     n_estimators=100,
        #     class_weight="balanced",
        #     random_state=42,
        # )),
    ])


def train_and_save():
    """모델 학습 후 pkl 저장"""
    # 데이터셋이 없으면 시드 데이터 자동 생성
    if not os.path.exists(CSV_PATH):
        print("📋 시드 데이터셋 생성 중...")
        sys.path.insert(0, BASE_DIR)
        from build_dataset import build_dataset
        build_dataset(CSV_PATH)

    # 데이터 로드
    texts, labels = load_dataset(CSV_PATH)

    if len(texts) < 20:
        print("❌ 데이터가 너무 적습니다 (최소 20건). 데이터셋을 확인하세요.")
        sys.exit(1)

    # 학습/테스트 분리 (80:20)
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,  # 클래스 비율 유지
    )
    print(f"\n🔀 데이터 분리: 학습 {len(X_train)}건 | 테스트 {len(X_test)}건")

    # 파이프라인 구성 및 학습
    print("\n🏋️  모델 학습 중...")
    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    # ── 성능 평가 ─────────────────────────────────────
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    report = classification_report(y_test, y_pred, target_names=["정상", "스미싱"])
    cm = confusion_matrix(y_test, y_pred)

    # 교차 검증 (5-fold)
    cv_scores = cross_val_score(pipeline, texts, labels, cv=5, scoring="f1")

    print(f"\n📊 테스트셋 성능")
    print(f"   정확도 (Accuracy): {accuracy:.4f}")
    print(f"   AUC-ROC:           {auc:.4f}")
    print(f"   F1 (5-fold CV):    {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    print(f"\n분류 보고서:\n{report}")
    print(f"혼동 행렬:\n{cm}")
    print(f"  (행: 실제 / 열: 예측) | [정상→정상, 정상→스미싱 / 스미싱→정상, 스미싱→스미싱]")

    # 보고서 저장
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(f"정확도: {accuracy:.4f}\n")
        f.write(f"AUC-ROC: {auc:.4f}\n")
        f.write(f"F1 (5-fold): {cv_scores.mean():.4f} ± {cv_scores.std():.4f}\n\n")
        f.write(report)
        f.write(f"\n혼동 행렬:\n{cm}\n")

    # 모델 저장
    joblib.dump(pipeline, MODEL_OUTPUT_PATH)
    print(f"\n✅ 모델 저장 완료: {MODEL_OUTPUT_PATH}")
    print(f"✅ 보고서 저장 완료: {REPORT_PATH}")

    return pipeline


if __name__ == "__main__":
    train_and_save()