"""A minimal agent: ask for access, list jobs, apply to one.

    python -m authyouragent keygen --name "Job-search assistant" > key.json
    # register key.json's "jwk" in the app, note the agent id
    AGENT_ID=ag_… KEY_FILE=key.json SITE_URL=https://jobs.example.com python examples/agent.py

SITE_ID defaults to SITE_URL's host; set it when they differ (local testing).
"""
import json
import os
import sys
from urllib.parse import urlsplit

from authyouragent import AgentClient, AgentError

key = json.load(open(os.environ["KEY_FILE"]))
key = key.get("agent_key", key)
site_url = os.environ["SITE_URL"].rstrip("/")
site = os.environ.get("SITE_ID") or urlsplit(site_url).hostname   # the name you approve

agent = AgentClient(base_url=os.environ.get("AUTHYOURAGENT_CLOUD", "https://authyouragent.com"),
                    agent_id=os.environ["AGENT_ID"],
                    privkey_pem=key.get("privkey_pem") or key["privkey"])
try:
    print("Asking for access; approve it on your phone…")
    agent.ensure_grant(site, scopes=["list", "apply"])
except AgentError as e:
    sys.exit(f"No access: {e}")

r = agent.request("GET", f"{site_url}/api/jobs", site=site)
if r.status_code != 200:
    sys.exit(f"The site refused: {r.status_code} {r.text[:300]}")
jobs = r.json()["jobs"]
print("Jobs:", jobs)
first = next(iter(jobs))
r = agent.request("POST", f"{site_url}/api/jobs/{first}/apply", stepup_action="apply", site=site)
print(r.status_code, r.json())
