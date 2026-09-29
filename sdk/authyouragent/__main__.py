"""`python -m authyouragent keygen --name "My agent"` — generate an agent key
locally (the private key never leaves this machine)."""
from .agent import _cli_main

if __name__ == "__main__":
    _cli_main()
