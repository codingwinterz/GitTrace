"""
conftest.py — test bootstrap.

Being at the repository root, this file puts the root on sys.path, so the tests
import `gittrace` without installing it.

FalkorDB settings need no placeholders any more: gittrace.graph.connection
defaults to local Docker (localhost:6379, no password) when neither the
environment nor `.env` sets them. The integration suites only ever run
against a local FalkorDB; a remote FALKORDB_HOST makes them skip.
"""
