"""Refusal detectors against the XSTest v2 human labels (2,250 completions).

    uv run --no-sync python benchmarks/detectors.py               # everything
    uv run --no-sync python benchmarks/detectors.py --skip-judge  # no LLM judge
    uv run --no-sync python benchmarks/detectors.py --only-guard  # just the Qwen3Guard rows

Every jailbreak probe decides "did the model answer the fictional restricted task?" with a
refusal detector, so the scanner's numbers are only as good as these detectors. XSTest v2
(Rottger et al., NAACL 2024) ships 450 prompts answered by 5 models with a human label per
completion (full compliance, full refusal, partial refusal); partial and full refusals are
both "refusal" here, as in the paper's refusal rate.

Detectors compared (all predict "refusal"):

* ``keyword``: the scanner's refusal phrase list (``refusal_keyword`` detector).
* ``xstest_strmatch``: the string match rule published with XSTest.
* ``classifier (LOMO)``: the scanner's hashed n-gram logistic regression, trained on four
  answering models and tested on the fifth (leave one model out), so no completion is seen
  in training. The bundled model is trained on all 2,250 and is not scored here.
* ``sklearn tfidf+LR (LOMO)``: scikit-learn TfidfVectorizer word 1-2 grams and
  LogisticRegression under the same split, as a reference implementation.
* ``protectai distilroberta``: ProtectAI/distilroberta-base-rejection-v1, a public
  fine-tuned refusal classifier (reference model, no training here; it was trained on
  other data, so it is fully held out).
* ``qwen3guard-gen-0.6b``: Qwen/Qwen3Guard-Gen-0.6B, a current open guard model, in its
  response-moderation mode (user prompt plus completion in, "Refusal: Yes/No" out;
  transformers on MPS, greedy, batches of 8). A reference that was not trained here.
* ``judge qwen3.5-2b``: the scanner's LLM judge with Qwen3.5-2B (Q4_K_M, llama.cpp,
  non-thinking mode, greedy). No verdict counts as "refusal" (the conservative choice for a
  scanner: a missing verdict never creates a finding). A judge call reads the prompt and
  a completion of up to 1,500 characters each, about 30 calls a minute on this laptop,
  so the judge runs on a seeded random sample (``--judge-sample``, default 500) and the
  keyword rule is scored on the same sample next to it.

Metrics are accuracy, precision, recall and F1 of the refusal class with 95% bootstrap
confidence intervals (1,000 resamples of the 2,250 completions, seed 0). Writes
benchmarks/results/detectors.json.
"""

from __future__ import annotations

import argparse
import json
import time
from collections.abc import Callable
from contextlib import ExitStack
from typing import Any

import numpy as np
from common import BENCH, MODELS, PRIMARY, RESULTS, XSTEST_MODELS, hardware, write_json, xstest_rows

from llm_vuln_scanner.detectors.judge import LlmJudge
from llm_vuln_scanner.detectors.refusal import RefusalModel, keyword_refusal, xstest_strmatch

PROTECTAI = "ProtectAI/distilroberta-base-rejection-v1"
GUARD = "Qwen/Qwen3Guard-Gen-0.6B"
JUDGE = MODELS[PRIMARY]


def metrics(y: np.ndarray, p: np.ndarray, n_boot: int = 1000, seed: int = 0) -> dict[str, Any]:
    """Accuracy, precision, recall and F1 of class 1, with percentile bootstrap CIs."""

    def point(yy: np.ndarray, pp: np.ndarray) -> tuple[float, float, float, float]:
        tp = float(np.sum((pp == 1) & (yy == 1)))
        fp = float(np.sum((pp == 1) & (yy == 0)))
        fn = float(np.sum((pp == 0) & (yy == 1)))
        acc = float(np.mean(pp == yy))
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        return acc, prec, rec, f1

    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(y), size=(n_boot, len(y)))
    boots = np.array([point(y[i], p[i]) for i in idx])
    out: dict[str, Any] = {}
    for j, name in enumerate(("accuracy", "precision", "recall", "f1")):
        lo, hi = np.percentile(boots[:, j], [2.5, 97.5])
        out[name] = round(point(y, p)[j], 4)
        out[name + "_ci95"] = [round(float(lo), 4), round(float(hi), 4)]
    out["predicted_refusal_rate"] = round(float(np.mean(p)), 4)
    return out


def lomo(
    rows: list[dict[str, Any]], fit_predict: Callable[[list[str], list[int], list[str]], np.ndarray]
) -> np.ndarray:
    """Leave-one-answering-model-out predictions for every row."""
    pred = np.zeros(len(rows), dtype=np.int64)
    for m in XSTEST_MODELS:
        tr = [i for i, r in enumerate(rows) if r["model"] != m]
        te = [i for i, r in enumerate(rows) if r["model"] == m]
        pred[te] = fit_predict(
            [rows[i]["completion"] for i in tr],
            [rows[i]["label"] for i in tr],
            [rows[i]["completion"] for i in te],
        )
    return pred


def ours_fit_predict(xtr: list[str], ytr: list[int], xte: list[str]) -> np.ndarray:
    model = RefusalModel.fit(xtr, ytr)
    return (model.predict_proba(xte) >= model.threshold).astype(np.int64)


def sklearn_fit_predict(xtr: list[str], ytr: list[int], xte: list[str]) -> np.ndarray:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)
    clf = LogisticRegression(max_iter=2000, C=10.0)
    clf.fit(vec.fit_transform(xtr), ytr)
    return np.asarray(clf.predict(vec.transform(xte)), dtype=np.int64)


def release_torch_memory() -> None:
    """Return cached accelerator memory before the next model loads (one model at a time)."""
    import gc

    import torch

    gc.collect()
    if torch.backends.mps.is_available():
        torch.mps.empty_cache()


def protectai(texts: list[str]) -> np.ndarray:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(PROTECTAI)
    model = AutoModelForSequenceClassification.from_pretrained(PROTECTAI).eval()
    refusal_label = next(i for i, name in model.config.id2label.items() if "REJ" in name.upper())
    out = []
    with torch.inference_mode():
        for i in range(0, len(texts), 32):
            enc = tok([t or " " for t in texts[i : i + 32]], truncation=True, max_length=512,
                      padding=True, return_tensors="pt")  # fmt: skip
            out.extend((model(**enc).logits.argmax(-1) == refusal_label).long().tolist())
    del model
    release_torch_memory()
    return np.asarray(out, dtype=np.int64)


def qwen3guard(rows: list[dict[str, Any]], batch: int = 8) -> tuple[np.ndarray, int]:
    """Qwen3Guard-Gen-0.6B response moderation: refusal when it answers "Refusal: Yes".

    Verdicts are cached in .bench-data (one JSON line per completion), so an interrupted
    run resumes. Returns the predictions and the number of outputs without a refusal field
    (counted as "complied", like the judge's missing verdicts)."""
    import re

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    cache_path = BENCH / "cache" / "guard-xstest-qwen3guard-gen-0.6b.jsonl"
    cache: dict[str, str] = {}
    if cache_path.exists():
        for line in cache_path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            cache[row["key"]] = row["output"]
    todo = [r for r in rows if f"{r['model']}/{r['id']}" not in cache]
    if todo:
        device = "mps" if torch.backends.mps.is_available() else "cpu"
        tok = AutoTokenizer.from_pretrained(GUARD, padding_side="left")
        model = AutoModelForCausalLM.from_pretrained(GUARD, dtype=torch.bfloat16).to(device).eval()
        with cache_path.open("a", encoding="utf-8") as f:
            for i in range(0, len(todo), batch):
                chunk = todo[i : i + batch]
                texts = [
                    tok.apply_chat_template(
                        [{"role": "user", "content": r["prompt"]},
                         {"role": "assistant", "content": r["completion"][:4000] or " "}],
                        tokenize=False,
                    )
                    for r in chunk
                ]  # fmt: skip
                enc = tok(texts, return_tensors="pt", padding=True).to(device)
                with torch.inference_mode():
                    out = model.generate(**enc, max_new_tokens=32, do_sample=False)
                for r, ids in zip(chunk, out[:, enc["input_ids"].shape[1] :], strict=True):
                    text = tok.decode(ids, skip_special_tokens=True)
                    key = f"{r['model']}/{r['id']}"
                    cache[key] = text
                    f.write(json.dumps({"key": key, "output": text}) + "\n")
                f.flush()
                if (i // batch) % 25 == 0:
                    print(f"  guard {i + len(chunk)}/{len(todo)} {time.strftime('%H:%M:%S')}", flush=True)
        del model
        release_torch_memory()
    labels = [re.search(r"Refusal: (Yes|No)", cache[f"{r['model']}/{r['id']}"]) for r in rows]
    missing = sum(m is None for m in labels)
    return np.asarray([int(m is not None and m.group(1) == "Yes") for m in labels], dtype=np.int64), missing


def judge(rows: list[dict[str, Any]], concurrency: int = 4) -> tuple[np.ndarray, int]:
    """Qwen3.5-2B judge verdicts, cached in .bench-data so reruns are free."""
    from concurrent.futures import ThreadPoolExecutor

    from llm_vuln_scanner.targets import LlamaCppServer

    cache_path = BENCH / "cache" / f"judge-xstest-{JUDGE.key}.jsonl"
    cache: dict[str, Any] = {}
    if cache_path.exists():
        for line in cache_path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            cache[row["key"]] = row["verdict"]
    todo = [r for r in rows if f"{r['model']}/{r['id']}" not in cache]
    if todo:
        with ExitStack() as stack:
            srv = stack.enter_context(LlamaCppServer(JUDGE.path(), parallel=concurrency, ctx_per_slot=2048,
                                                     extra_args=JUDGE.extra_args,
                                                     log_path=str(BENCH / "logs" / "llama-judge.log")))  # fmt: skip
            j = LlmJudge(srv.target("judge"))
            f = cache_path.open("a", encoding="utf-8")
            stack.callback(f.close)

            def one(r: dict[str, Any]) -> None:
                v = j.complied(r["prompt"], r["completion"])
                key = f"{r['model']}/{r['id']}"
                cache[key] = v
                f.write(json.dumps({"key": key, "verdict": v}) + "\n")
                f.flush()

            with ThreadPoolExecutor(concurrency) as pool:
                for k, _ in enumerate(pool.map(one, todo), 1):
                    if k % 250 == 0:
                        print(f"  judge {k}/{len(todo)} {time.strftime('%H:%M:%S')}", flush=True)
    verdicts = [cache[f"{r['model']}/{r['id']}"] for r in rows]
    none = sum(v is None for v in verdicts)
    return np.asarray([0 if v else 1 for v in verdicts], dtype=np.int64), none


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-judge", action="store_true")
    ap.add_argument("--skip-reference", action="store_true", help="skip the ProtectAI model")
    ap.add_argument("--skip-guard", action="store_true", help="skip Qwen3Guard-Gen-0.6B")
    ap.add_argument(
        "--only-guard",
        action="store_true",
        help="run only the Qwen3Guard rows and merge them into detectors.json",
    )
    ap.add_argument("--judge-sample", type=int, default=500, help="completions the judge grades (seeded)")
    args = ap.parse_args()
    rows = xstest_rows()
    y = np.asarray([r["label"] for r in rows], dtype=np.int64)
    texts = [r["completion"] for r in rows]
    results: dict[str, Any] = {}

    def record(name: str, fn: Callable[[], np.ndarray], **extra: Any) -> np.ndarray:
        t0 = time.perf_counter()
        p = fn()
        dt = time.perf_counter() - t0
        results[name] = {**metrics(y, p), "seconds": round(dt, 2), **extra}
        print(f"{name:28s} acc {results[name]['accuracy']:.3f}  F1 {results[name]['f1']:.3f}  {dt:7.1f} s")
        return p

    record(
        "keyword", lambda: np.asarray([keyword_refusal(t) or not t.strip() for t in texts], dtype=np.int64)
    )
    record("xstest_strmatch", lambda: np.asarray([xstest_strmatch(t) for t in texts], dtype=np.int64))
    record("classifier (LOMO)", lambda: lomo(rows, ours_fit_predict), split="leave one answering model out")
    record(
        "sklearn tfidf+LR (LOMO)",
        lambda: lomo(rows, sklearn_fit_predict),
        split="leave one answering model out",
    )
    if args.only_guard:
        previous = json.loads((RESULTS / "detectors.json").read_text(encoding="utf-8"))
        results.update(previous["detectors"])
    if not args.skip_reference and not args.only_guard:
        record("protectai distilroberta", lambda: protectai(texts), model=PROTECTAI)
    if not args.skip_guard:
        t0 = time.perf_counter()
        pg, missing = qwen3guard(rows)
        results["qwen3guard-gen-0.6b"] = {**metrics(y, pg), "seconds": round(time.perf_counter() - t0, 2),
                                          "model": GUARD, "no_refusal_field": missing}  # fmt: skip
        print(f"{'qwen3guard-gen-0.6b':28s} acc {results['qwen3guard-gen-0.6b']['accuracy']:.3f}  "
              f"F1 {results['qwen3guard-gen-0.6b']['f1']:.3f}")  # fmt: skip
    if not args.skip_judge and not args.only_guard:
        idx = np.sort(
            np.random.default_rng(0).choice(len(rows), size=min(args.judge_sample, len(rows)), replace=False)
        )
        sub = [rows[i] for i in idx]
        ys = y[idx]
        t0 = time.perf_counter()
        pj, none = judge(sub)
        dt = time.perf_counter() - t0
        pk = np.asarray(
            [keyword_refusal(r["completion"]) or not r["completion"].strip() for r in sub], dtype=np.int64
        )
        sample = f"seeded random sample of {len(sub)}"
        results[f"judge {JUDGE.key}"] = {**metrics(ys, pj), "seconds": round(dt, 2), "sample": sample,
                                         "no_verdict": none, "model": f"{JUDGE.label} (llama.cpp, non-thinking)"}  # fmt: skip
        results["keyword (judge sample)"] = {**metrics(ys, pk), "seconds": 0.0, "sample": sample}
        for name in (f"judge {JUDGE.key}", "keyword (judge sample)"):
            print(f"{name:28s} acc {results[name]['accuracy']:.3f}  F1 {results[name]['f1']:.3f}")
    per_model = {m: {"n": sum(r["model"] == m for r in rows),
                     "refusal_rate": round(float(np.mean([r["label"] for r in rows if r["model"] == m])), 4)}
                 for m in XSTEST_MODELS}  # fmt: skip
    write_json("detectors.json", {
        "dataset": "XSTest v2 completions (paul-rottger/xstest), human labels",
        "n": len(rows), "refusal_rate": round(float(y.mean()), 4), "per_answering_model": per_model,
        "bootstrap": {"resamples": 1000, "seed": 0}, "detectors": results, "hardware": hardware(),
    })  # fmt: skip


if __name__ == "__main__":
    main()
