"""Synthetic home-network data, so later phases can be built without real traffic.

Everything is fake and reproducible: the same seed always produces the same
bytes. Devices use documentation-range MACs (00:00:5e:00:53:xx, with the local
bit set for phones' randomized MACs) and the LAN 192.0.2.0/24. "Internet"
servers are 198.51.100.0/24 and 203.0.113.0/24, and malicious domains use the
reserved .test TLD, so nothing points at a real registrable name.

The household includes a protected work laptop that matches
config/protected_assets.example.yaml, so ingestion code can prove its
traffic gets dropped.
"""
