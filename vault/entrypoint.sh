#!/bin/sh
# Virtual display, then the broker. The owner sees this display during a take
# over through the Auth Your Agent phone viewer (see screen.py).
set -e
SIZE="${VAULT_SIZE:-1280x900}"; SCALE="${VAULT_SCALE:-1}"
SCREEN=$(python3 -c "
w,h=map(int,'$SIZE'.split('x')); s=float('$SCALE')
if w<500: w,h=500,round(h*500/w)   # Chromium's minimum window width
print(f'{round(w*s)}x{round(h*s)}')")
# Keep the display up: Xvfb can be killed from outside (a `pkill Xvfb` on the
# host also matches this container's), and Chromium dies with its display.
# The broker restarts Chromium once the display is back (Vault.ensure_chrome).
# Each start clears the old lock, which a dead Xvfb (or a container restart,
# which keeps /tmp) leaves behind. Nothing else uses display :0 here.
(while :; do
    rm -f /tmp/.X0-lock /tmp/.X11-unix/X0
    Xvfb :0 -screen 0 "${SCREEN}x24" -nolisten tcp
    sleep 1
done) &
export DISPLAY=:0
exec python3 /app/broker.py
