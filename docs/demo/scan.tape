# Records docs/demo/scan.gif from a real run: `vhs docs/demo/scan.tape` from the repo root.
Output docs/demo/scan.gif
Set Shell "bash"
Set FontSize 15
Set Width 1300
Set Height 640
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 22ms

Hide
Type `export PS1='$ ' VIRTUAL_ENV_DISABLE_PROMPT=1 && source .venv/bin/activate && rm -rf demo-reports` Enter
Sleep 4s
Type `clear` Enter
Sleep 1s
Show
Type `llm-vuln-scanner scan --target naive --sample 4 --seed 1 --fail-on high --out demo-reports; echo "exit code $?"` Enter
Sleep 9s
Type `jq -c '.runs[0].results[] | {ruleId, level, owasp: .properties.owasp, atlas: .properties.atlas}' demo-reports/scan.sarif | head -4` Enter
Sleep 4s
Hide
Type `rm -rf demo-reports` Enter
