import sys


def pytest_configure(config):
    sys._pytest_running = True
