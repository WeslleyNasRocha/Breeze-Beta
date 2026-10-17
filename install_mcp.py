#!/usr/bin/env python3
"""
Quick installer for Breeze MCP Server.
Configures Claude Desktop, Cursor, Antigravity, and Cline automatically.

Usage:
    python3 install_mcp.py
    python3 install_mcp.py --host 192.168.1.50 --code 0303
    python3 install_mcp.py --status
    python3 install_mcp.py --uninstall
"""
import sys
from breeze_mcp import install_cli

if __name__ == "__main__":
    sys.exit(install_cli(sys.argv[1:]))
