"""Auth Your Agent — Python SDK.

Two halves:

* :mod:`authyouragent.agent` — for AI agents. Holds the agent's private key,
  asks the user's phone for approval, and signs every request (DPoP).
* :mod:`authyouragent.site`  — for websites. Verifies that a request really
  comes from an agent the user approved, and whether a sensitive action was
  confirmed (step-up).

Quick start (agent)::

    from authyouragent import AgentClient
    agent = AgentClient(base_url="https://authyouragent.com",
                        agent_id="ag_…", privkey_pem=open("agent.pem").read())
    agent.ensure_grant("jobs.example.com", scopes=["list"])
    r = agent.request("GET", "https://jobs.example.com/api/jobs")

Quick start (site)::

    from authyouragent import SiteVerifier, AuthError
    verifier = SiteVerifier("https://authyouragent.com")
    auth = verifier.verify(request)      # raises AuthError

Documentation: https://authyouragent.com/docs
"""

from .agent import AgentClient, AgentError, keygen, agent_jwk
from .site import SiteVerifier, AuthError, Auth

__all__ = ["AgentClient", "AgentError", "keygen", "agent_jwk",
           "SiteVerifier", "AuthError", "Auth"]
__version__ = "0.3.17"
DEFAULT_CLOUD = "https://authyouragent.com"
