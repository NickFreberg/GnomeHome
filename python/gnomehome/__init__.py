"""GnomeHome: hardened home network detection and response.

The Python side owns scheduled data jobs (nmap orchestration, enrichment,
risk scoring, analytics). SQLite in WAL mode is the contract with the Rust
side; neither language calls the other directly.
"""

__version__ = "0.1.0"
