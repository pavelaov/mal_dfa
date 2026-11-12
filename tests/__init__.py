"""Unit tests for the vigor_dfa reference (stdlib ``unittest``).

All tests are deterministic: every pseudo-random draw uses a fixed seed, and the one rejection-sampling test injects a deterministic byte source. Run from the artifact root with::

    python -m unittest discover -s tests
"""
