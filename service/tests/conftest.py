def pytest_configure(config):
    config.addinivalue_line(
        "markers", "live: tests that call the real NIH RAS test environment (need RAS_* env vars; skipped otherwise)"
    )
