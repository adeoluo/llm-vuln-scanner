# Records docs/demo/demo-app.gif from a real run: `vhs docs/demo/demo-app.tape` from the repo root.
Output docs/demo/demo-app.gif
Set Shell "bash"
Set FontSize 15
Set Width 1300
Set Height 420
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 22ms

Hide
Type `export PS1='$ ' VIRTUAL_ENV_DISABLE_PROMPT=1 && uv sync -q && source .venv/bin/activate && rm -rf demo-reports` Enter
Sleep 4s
Type `llm-vuln-scanner demo-app --port 18088 >/dev/null 2>&1 & llm-vuln-scanner demo-app --hardened --port 18089 >/dev/null 2>&1 &` Enter
Sleep 4s
Type `clear` Enter
Sleep 1s
Show
Type `P="--profile examples/demo-app.json --sample 6 --out demo-reports --quiet"` Enter
Type `llm-vuln-scanner scan --target app:http://127.0.0.1:18088 $P --name vulnerable` Enter
Sleep 5s
Type `llm-vuln-scanner scan --target app:http://127.0.0.1:18089 $P --name hardened` Enter
Sleep 5s
Type `llm-vuln-scanner compare demo-reports/vulnerable.json demo-reports/hardened.json` Enter
Sleep 7s
Hide
Type `kill %1 %2; rm -rf demo-reports` Enter
Sleep 1s
