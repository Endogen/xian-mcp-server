#!/bin/bash
echo "Building XIAN MCP Server..."
docker build -t xian-mcp-server .
echo "Build complete! See README for configuration instructions."