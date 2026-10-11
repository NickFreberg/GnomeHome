"""Responders: modules that act on the network (Phase 7).

Every module here imports the shared guard and calls ``guard.require_allowed()``
before acting, which refuses (and audits, by label) anything aimed at a
protected device. ``python/tests/test_architecture.py`` checks the import.
"""
