# VHS tape for the iAnonymiser README demo.
#
# Install VHS: https://github.com/charmbracelet/vhs (requires ffmpeg + ttyd)
#
# Generate the GIF (run from the repository root, no server/Docker needed —
# the CLI talks to the anonymization engine directly):
#   vhs docs/demo.tape
#
# Uses docs/demo-source.txt as the sample input.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 600
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 40ms

Type `cat docs/demo-source.txt`
Enter
Sleep 2s

Type `python cli.py anonymize docs/demo-source.txt`
Enter
Sleep 3s

Type `clear`
Enter
Type `# Paste the anonymized log into any LLM. It answers using the placeholders:`
Enter
Sleep 1s

Type `echo 'The root cause is on [HOST_001]: it dropped the healthcheck from [IP_001]. Revoke [KEY_001] now.' | python cli.py deanonymize - --mapping docs/demo-source.txt.mapping.json`
Enter
Sleep 3s
