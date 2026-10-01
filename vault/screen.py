"""Screen take over: the owner uses the vault's browser from their phone while
the agent is disconnected from it.

Nothing is attached to the browser during the take over. The picture comes
from the virtual display, and the owner's taps and typing arrive as ordinary
mouse and keyboard events, so the site sees a person using a normal browser.

Only a fixed set of inputs reaches the browser: taps, scrolling, typed text,
a few editing keys, and Back. No modifier keys (Ctrl, Alt, ...) can be sent,
so browser shortcuts (downloads, history, developer tools, ...) cannot be
triggered from the phone.
"""
import asyncio
import hashlib
import io
import json
import os

from PIL import Image
from Xlib import X, display

FPS = 6
JPEG_Q = 70
SEND_W = 750            # frame width sent to the phone (pixels)

# viewer key name -> X key name
KEYS = {"Enter": "Return", "Backspace": "BackSpace", "Tab": "Tab", "Escape": "Escape",
        "ArrowUp": "Up", "ArrowDown": "Down", "ArrowLeft": "Left", "ArrowRight": "Right"}


async def xdo(*args):
    p = await asyncio.create_subprocess_exec("xdotool", *args, env={**os.environ},
                                             stdout=asyncio.subprocess.DEVNULL,
                                             stderr=asyncio.subprocess.DEVNULL)
    await p.wait()


class Screen:
    def __init__(self):
        self.d = display.Display()
        self.root = self.d.screen().root
        g = self.root.get_geometry()
        self.w, self.h = g.width, g.height

    def grab(self):
        raw = self.root.get_image(0, 0, self.w, self.h, X.ZPixmap, 0xFFFFFFFF).data
        return raw

    def jpeg(self, raw):
        im = Image.frombytes("RGB", (self.w, self.h), raw, "raw", "BGRX")
        if self.w > SEND_W:
            im = im.resize((SEND_W, round(self.h * SEND_W / self.w)), Image.LANCZOS)
        buf = io.BytesIO()
        im.save(buf, "JPEG", quality=JPEG_Q)
        return buf.getvalue(), im.size


async def run(ws, restart_url, log, watcher=None):
    """Serve one take over on an open relay websocket. Returns how it ended:
    done / cancelled / expired / agent_left."""
    import base64
    scr = Screen()
    await ws.send(json.dumps({"t": "mode", "mode": "screen"}))
    stop = asyncio.Event()
    size = {"w": scr.w, "h": scr.h}

    async def frames():
        last = None
        while not stop.is_set():
            try:
                raw = await asyncio.to_thread(scr.grab)
                h = hashlib.blake2b(raw, digest_size=16).digest()
                if h != last:
                    last = h
                    data, (fw, fh) = await asyncio.to_thread(scr.jpeg, raw)
                    size.update(w=fw, h=fh)
                    await ws.send(json.dumps({"t": "frame", "w": fw, "h": fh,
                                              "data": base64.b64encode(data).decode()}))
            except Exception as e:
                log("frame error:", type(e).__name__, e)
            await asyncio.sleep(1 / FPS)

    def to_screen(x, y):
        k = scr.w / size["w"]
        return (str(max(0, min(scr.w - 1, round(float(x) * k)))),
                str(max(0, min(scr.h - 1, round(float(y) * k)))))

    async def serve():
        """Apply the owner's input until the relay says how the take over ended."""
        async for raw in ws:
            m = json.loads(raw)
            k = m.get("t")
            if k == "click":
                x, y = to_screen(m["x"], m["y"])
                await xdo("mousemove", x, y, "click", "1")
            elif k in ("text", "set"):
                # "set" comes from viewers built for the old field overlay; in
                # screen mode there is no field value to replace, so type it.
                text = str(m.get("text", m.get("value", "")))[:500]
                text = "".join(c for c in text if c == "\n" or c >= " ")
                if text:
                    await xdo("type", "--delay", "25", "--", text)
            elif k == "key" and m.get("key") in KEYS:
                await xdo("key", "--clearmodifiers", KEYS[m["key"]])
            elif k == "scroll":
                dy = float(m.get("dy", 0))
                n = max(1, min(15, round(abs(dy) / 100)))
                await xdo("mousemove", str(scr.w // 2), str(scr.h // 2),
                          "click", "--repeat", str(n), "--delay", "20", "5" if dy > 0 else "4")
            elif k == "nav" and m.get("to") == "back":
                await xdo("key", "--clearmodifiers", "alt+Left")
            elif k == "nav" and m.get("to") == "restart":
                await restart_url()
            elif k in ("done", "cancelled", "expired", "agent_left"):
                return k
        return "agent_left"

    task = asyncio.create_task(frames())
    watch = asyncio.create_task(watcher(ws)) if watcher else None

    def signed_in():
        # The watcher returns True once it has seen the sign-in finish.
        return bool(watch and watch.done() and not watch.cancelled()
                    and watch.exception() is None and watch.result())
    try:
        result = await serve()
    except Exception as e:
        # The relay dropped without a close frame; decided below.
        log("relay closed:", type(e).__name__, e)
        result = "agent_left"
    finally:
        stop.set()
        task.cancel()
        if watch and not watch.done():
            watch.cancel()
        try:
            scr.d.close()
        except Exception:
            pass
    # If the vault saw the sign-in finish, the take over succeeded even when the
    # relay closed before (or instead of) confirming it.
    if result == "agent_left" and signed_in():
        result = "done"
    return result
