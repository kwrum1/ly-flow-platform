#!/bin/bash
set -e

echo "=== Ly-Flow Platform API Tests ==="
echo ""

echo "1. Testing server health..."
curl -s http://localhost:8080/ | tee /tmp/health.log
echo ""

echo "2. Testing assets API..."
curl -s http://localhost:8080/api/v1/assets | tee /tmp/assets.log
echo ""

echo "3. Testing frontend..."
curl -s http://localhost:3000/ | head -5
echo ""

echo "=== All tests completed ==="
