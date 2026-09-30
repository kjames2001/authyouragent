#!/bin/sh
# Virtual display, then the broker. The owner sees this display during a take
# over through the Auth Your Agent phone viewer (see screen.py).
set -e
SIZE="${VAULT_SIZE:-1280x900}"; SCALE="${VAULT_SCALE:-1}"
SCREEN=$(python3 -c "
w,h=map(int,'$SIZE'.split('x')); s=float('$SCALE')
if w<500: w,h=500,round(h*500/w)   # Chromium's minimum window width
print(f'{round(w*s)}x{round(h*s)}')")
Xvfb :0 -screen 0 "${SCREEN}x24" -nolisten tcp &
export DISPLAY=:0
exec python3 /app/broker.py
