"""A minimal site that accepts Auth Your Agent agents (FastAPI).

    pip install fastapi uvicorn ./sdk
    SITE_ID=jobs.example.com PUBLIC_URL=https://jobs.example.com \
        uvicorn examples.site_fastapi:app --port 8000

Agents must ask for access to SITE_ID; PUBLIC_URL is the address they call.
"""
import os

from fastapi import FastAPI, HTTPException, Request

from authyouragent import AuthError, SiteVerifier

SITE_ID = os.environ.get("SITE_ID", "jobs.example.com")
verifier = SiteVerifier(os.environ.get("AUTHYOURAGENT_CLOUD", "https://authyouragent.com"),
                        expected_audience=SITE_ID,
                        public_base_url=os.environ.get("PUBLIC_URL", f"https://{SITE_ID}"))
JOBS = {"j1": "Lighthouse keeper", "j2": "Bridge inspector"}
app = FastAPI(title="Example job board")


def agent_for(request: Request, scope: str):
    try:
        auth = verifier.verify(request)
    except AuthError as e:
        raise HTTPException(401, {"error": e.error})
    if scope not in auth.scopes:
        raise HTTPException(403, {"error": "insufficient_scope"})
    return auth


@app.get("/api/jobs")
def list_jobs(request: Request):
    auth = agent_for(request, "list")
    return {"jobs": JOBS, "agent": auth.agent_name, "for_user": auth.user_id,
            "name": auth.user_info.get("user:name")}


@app.post("/api/jobs/{job_id}/apply")
def apply(job_id: str, request: Request):
    if job_id not in JOBS:                      # before verify: don't burn a step-up
        raise HTTPException(404, {"error": "no such job"})
    auth = agent_for(request, "apply")
    if not auth.stepup:
        raise HTTPException(403, {"error": "stepup_required"})
    return {"applied": True, "job": JOBS[job_id]}
