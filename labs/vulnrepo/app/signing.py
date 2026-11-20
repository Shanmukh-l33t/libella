"""Message signing helper for the fixture service.

The key material is a fake marker block so secret scanners have something to
find; the body is dummy text, not a valid key, and it signs nothing.
"""

SIGNING_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
FAKEFAKEFAKEFAKEfakefakefakeFAKEFAKEFAKEFAKEfakefakefakeFAKEFAKEFAKEFAKE
-----END RSA PRIVATE KEY-----
"""
