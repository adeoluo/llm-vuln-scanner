# Records docs/demo/compare.gif from a real run: `vhs docs/demo/compare.tape` from the repo root.
Output docs/demo/compare.gif
Set Shell "bash"
Set FontSize 15
Set Width 1300
Set Height 560
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 22ms

Hide
Type `export PS1='$ ' VIRTUAL_ENV_DISABLE_PROMPT=1 && source .venv/bin/activate && cd benchmarks/results/scans` Enter
Sleep 4s
Type `clear` Enter
Sleep 1s
Show
Type `jq -c '{target, summary: .summary | {attempts, successes, errors}}' qwen2.5-1.5b.json smollm2-1.7b.json` Enter
Sleep 3s
Type `llm-vuln-scanner compare qwen2.5-1.5b.json smollm2-1.7b.json` Enter
Sleep 8s
