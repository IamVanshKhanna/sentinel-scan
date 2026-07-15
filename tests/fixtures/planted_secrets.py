"""
Fixture file for testing secret detection.

Every value below is a FAKE placeholder that matches the *shape* of a real
credential, not a real one. These exist so the test suite can assert the
detectors fire correctly — do not reuse these strings anywhere real.
"""

# fake AWS access key (correct format, not a live credential)
AWS_ACCESS_KEY = "AKIAABCDEFGHIJKLMNOP"

# fake GitHub personal access token (correct format, not live)
GITHUB_TOKEN = "ghp_00000000000000000000000000000000000A"

# fake generic secret assignment
api_key = "not_a_real_secret_but_looks_like_one"

FAKE_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
FAKEKEYDATAFAKEKEYDATAFAKEKEYDATAFAKEKEYDATA
-----END RSA PRIVATE KEY-----"""

# fake Stripe live key (correct format, not live)
STRIPE_KEY = "sk_live_FAKEFAKEFAKEFAKEFAKEFAKE"

# fake JWT (correct structural shape, not a real signed token)
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.fake_signature_not_real"

# fake DB connection string with embedded credentials
DB_URL = "postgres://fakeuser:fakepassword@db.example.com:5432/mydb"
