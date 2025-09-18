"""
api package for the FastAPIService.

This module exposes the FastAPI 'app' instance for ASGI servers and tooling.
"""

from .main import app as app  # single explicit export to avoid redefinition (flake8 F811)

# PUBLIC_INTERFACE
def get_app():
    """Return the FastAPI application instance."""
    return app
