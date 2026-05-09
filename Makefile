.PHONY: help build-all build-probe build-dpi build-server build-frontend build-agent images clean

IMAGE_PREFIX = ly-flow

help:
	@echo "Ly-Flow Platform Build Commands"
	@echo "=============================="
	@echo "make build-probe      - Build ly-probe image"
	@echo "make build-dpi        - Build ly-dpi-engine image"
	@echo "make build-server     - Build ly-server image"
	@echo "make build-frontend   - Build ly-frontend image"
	@echo "make build-agent      - Build ly-agent image"
	@echo "make build-all        - Build all images"
	@echo "make images          - List ly-flow images"
	@echo "make clean            - Remove all ly-flow images"

build-probe:
	docker build -f probe/Dockerfile -t $(IMAGE_PREFIX)/probe:latest .

build-dpi:
	docker build -f dpi-engine/Dockerfile -t $(IMAGE_PREFIX)/dpi-engine:latest .

build-server:
	docker build -f server/Dockerfile -t $(IMAGE_PREFIX)/server:latest .

build-frontend:
	docker build -f frontend/Dockerfile -t $(IMAGE_PREFIX)/frontend:latest .

build-agent:
	docker build -f agent/Dockerfile -t $(IMAGE_PREFIX)/agent:latest .

build-all: build-probe build-dpi build-server build-frontend build-agent

images:
	docker images | grep $(IMAGE_PREFIX)

clean:
	docker rmi -f $$(docker images -q $(IMAGE_PREFIX)/*) 2>/dev/null || true
