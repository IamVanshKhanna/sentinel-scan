"""A file with no secrets — used to assert the scanner doesn't false-positive."""


def greet(name: str) -> str:
    return f"Hello, {name}!"


CONFIG = {
    "timeout": 30,
    "retries": 3,
    "base_url": "https://api.example.com",
}
