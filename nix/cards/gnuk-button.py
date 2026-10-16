# Runs Gnuk's emulation and presses its acknowledge button whenever it asks.
#
# The emulation reads the button from standard input: any line after its prompt counts as a
# press. A press has to wait a moment, though. The CCID thread listens for it only between
# transfers, and right after the prompt it is still sending the time extension that tells
# the host to wait; a press in that window is dropped by the emulation and the operation
# times out with 6600, where a real button's interrupt would stay pending. Half a second is
# far longer than that transfer and far shorter than the token's timeout of 7 x 1.95 s.
import os
import subprocess
import sys
import time

PROMPT = b"Type RET to acknowledge"

gnuk = subprocess.Popen(sys.argv[1:], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
seen = b""
while True:
    chunk = os.read(gnuk.stdout.fileno(), 4096)
    if not chunk:
        sys.exit(gnuk.wait())
    sys.stdout.buffer.write(chunk)
    sys.stdout.flush()
    seen = (seen + chunk)[-256:]
    if PROMPT in seen:
        seen = b""
        time.sleep(0.5)
        gnuk.stdin.write(b"\n")
        gnuk.stdin.flush()
