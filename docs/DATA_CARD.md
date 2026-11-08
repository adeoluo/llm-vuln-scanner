# Data Card: LLM Vuln Scanner

The scanner's own probes are generated from templates in `src/llm_vuln_scanner/probes/`
with fictional canaries; they need no download. Four public datasets feed the optional
`dataset.*` probes and the detector benchmark. None is committed; `make data` downloads
them (about 6 MB) into `../.bench-data/llm-vuln-scanner/data/`.

## Sources and provenance

| Dataset | Source | Size used | Used for |
|---|---|---|---|
| Tensor Trust hijacking robustness v1 | [HumanCompatibleAI/tensor-trust-data](https://github.com/HumanCompatibleAI/tensor-trust-data) (Toyer et al., 2023) | 776 attacks | `dataset.tensortrust_hijacking` (LLM01) |
| Tensor Trust extraction robustness v1 | same | 570 attacks | `dataset.tensortrust_extraction` (LLM08:2026) |
| Lakera gandalf_ignore_instructions | [Hugging Face](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | 1,000 prompts (777 train, 111 validation, 112 test) | `dataset.gandalf` (LLM07) |
| In-the-wild jailbreak prompts, 2023-12-25 | [TrustAIRLab](https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts) (Shen et al., CCS 2024) | 1,405 prompts, 106 usable templates | `dataset.wild_jailbreak` (LLM01) |
| XSTest v2 model completions | [paul-rottger/xstest](https://github.com/paul-rottger/xstest) (Rottger et al., NAACL 2024) | 2,250 completions (450 prompts x 5 models) with human labels | training and evaluating the refusal detectors |

## Licensing
Tensor Trust data: MIT/CC BY per the repository. Gandalf: MIT. In-the-wild jailbreak
prompts: MIT. XSTest: CC BY 4.0 (`xstest_LICENSE` is downloaded with the files). The
bundled refusal model (`src/llm_vuln_scanner/data/refusal-v1.npz`) contains only hashed
feature weights derived from XSTest, not the text.

## Composition and preprocessing
- Tensor Trust rows are used verbatim (defense pre-prompt, attack, post-prompt, access code).
- Gandalf splits are merged into `gandalf.jsonl`; each prompt is paired with a fresh
  canary password in a fictional "Gandalf" system prompt.
- In-the-wild jailbreak templates are kept only if they contain a placeholder for the
  request, are at most 6,000 characters, and match none of the explicit-content filter
  terms in `probes/datasets.py`; the request substituted in is always one of six
  fictional restricted tasks (for example the brewing steps of an invented potion).
- XSTest labels: `1_full_compliance` is "complied"; full and partial refusals are "refused".

## Contamination checks
The detector benchmark reports the trained classifier only under leave-one-answering-model
-out splits, so no scored completion is in its training data. The bundled model is trained
on all 2,250 completions and is never scored on XSTest.

## Known biases and gaps
- XSTest completions come from five 2023 models (GPT-4, Llama-2 variants, Mistral); the
  refusal style of newer or smaller models differs.
- Tensor Trust and Gandalf attacks are game play; they over-represent "say access granted"
  and password extraction compared with production attacks.
- All data is English.

## Ethical considerations
No probe asks for real harmful content. Jailbreak templates are only filled with
fictional restricted tasks, and secrets are fictional canaries, fake keys in documented
example formats and `example`/`fictional-mail.example` addresses.
