#!/bin/bash
set -e

PROJECT="ly-flow"

build_all() {
    echo "Building all ly-flow images..."
    docker build -f probe/Dockerfile -t ${PROJECT}/probe:latest .
    docker build -f dpi-engine/Dockerfile -t ${PROJECT}/dpi-engine:latest .
    docker build -f server/Dockerfile -t ${PROJECT}/server:latest .
    docker build -f frontend/Dockerfile -t ${PROJECT}/frontend:latest .
    docker build -f agent/Dockerfile -t ${PROJECT}/agent:latest .
    echo "Build complete!"
    docker images | grep ${PROJECT}
}

case "$1" in
    probe) docker build -f probe/Dockerfile -t ${PROJECT}/probe:latest . ;;
    dpi-engine) docker build -f dpi-engine/Dockerfile -t ${PROJECT}/dpi-engine:latest . ;;
    server) docker build -f server/Dockerfile -t ${PROJECT}/server:latest . ;;
    frontend) docker build -f frontend/Dockerfile -t ${PROJECT}/frontend:latest . ;;
    agent) docker build -f agent/Dockerfile -t ${PROJECT}/agent:latest . ;;
    all) build_all ;;
    images) docker images | grep ${PROJECT} ;;
    *) echo "Usage: $0 {probe|dpi-engine|server|frontend|agent|all|images}" ;;
esac
