# VHS tape for the iAnonymiser README demo.
#
# Install VHS: https://github.com/charmbracelet/vhs (requires ffmpeg + ttyd)
#
# Generate the GIF (run from the repository root):
#   1. docker run -d --name ianonymiser -p 5000:5000 ghcr.io/vanti7/ianonymiser:latest
#   2. vhs docs/demo.tape
#   3. docker stop ianonymiser && docker rm ianonymiser
#
# Uses docs/demo-source.txt as the sample input. The JSON payloads below
# hardcode that file's content (with \n escapes) so the tape has no extra
# runtime dependency to record it (only python3, to pretty-print the
# JSON response — already required to run iAnonymiser itself).

Output docs/demo.gif

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 18
Set Width 1200
Set Height 680
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 40ms

Type `cat docs/demo-source.txt`
Enter
Sleep 2s

Type `curl -s -X POST http://localhost:5000/anonymize -H 'Content-Type: application/json' -d '{"text": "2026-07-08 09:14:22 [ERROR] Connection from 10.0.4.17 refused by firewall\n2026-07-08 09:14:23 [WARN]  Host db-prod-02.internal.corp did not respond to healthcheck\n2026-07-08 09:14:25 [INFO]  Retrying with fallback credentials user=jdupont@acme-corp.com\n2026-07-08 09:14:26 [ERROR] Auth failed, API key sk-proj-9fKp2XyzAbC1234567890 rejected"}' | python3 -c "import json,sys; print(json.load(sys.stdin)['anonymized_text'])"`
Enter
Sleep 3s

Type `clear`
Enter
Type `# Paste the anonymized log into any LLM. It answers using the placeholders:`
Enter
Sleep 1s
Type `echo 'The root cause is on [HOST_001]: it dropped the healthcheck from [IP_001]. Revoke [KEY_001] now.'`
Enter
Sleep 2s

Type `curl -s -X POST http://localhost:5000/deanonymize -H 'Content-Type: application/json' -d '{"text": "The root cause is on [HOST_001]: it dropped the healthcheck from [IP_001]. Revoke [KEY_001] now."}' | python3 -c "import json,sys; print(json.load(sys.stdin)['original_text'])"`
Enter
Sleep 3s
