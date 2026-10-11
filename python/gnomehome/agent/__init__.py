"""The weekly AI check-in agent (FR-18), run as an Azure Container Apps job.

It reads one document, the week's curated summary (``gnomehome.summary``),
asks Azure OpenAI in the owner's tenant for a plain-English check-in, and writes
the report back to storage. It never sees raw logs, never runs on the Pi, and
can change nothing: any action it suggests is only a suggestion, which the Pi
turns into an ask-first playbook run waiting for the owner's approval.

The summary contains text that devices control (hostnames, domains), so the
design assumes prompt injection (R-04): see ``prompt.py``.
"""
