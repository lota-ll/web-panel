#!/bin/bash
# ============================================================================
# EcoCharge Web Portal - Deployment Script
# ============================================================================
# Для розгортання на сервері 192.168.125.100
# Частина кіберполігону EVSE CTF
# ============================================================================

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         EcoCharge Web Portal - Deployment Script              ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}[!] Running without root privileges. Some operations may fail.${NC}"
fi

# Check Docker
echo -e "${GREEN}[1/5]${NC} Checking Docker installation..."
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}[!] Docker not found. Installing...${NC}"
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
else
    echo -e "${GREEN}[✓]${NC} Docker is installed"
fi

# Check Docker Compose
echo -e "${GREEN}[2/5]${NC} Checking Docker Compose..."
if ! docker compose version &> /dev/null; then
    echo -e "${YELLOW}[!] Docker Compose not found. Installing...${NC}"
    apt-get update && apt-get install -y docker-compose-plugin
else
    echo -e "${GREEN}[✓]${NC} Docker Compose is installed"
fi

# Check network connectivity to CitrineOS
echo -e "${GREEN}[3/5]${NC} Checking connectivity to CitrineOS (192.168.20.20)..."
if ping -c 1 192.168.20.20 &> /dev/null; then
    echo -e "${GREEN}[✓]${NC} CitrineOS is reachable"
    
    # Check specific ports
    if nc -zv 192.168.20.20 8090 2>&1 | grep -q 'succeeded'; then
        echo -e "${GREEN}[✓]${NC} Hasura GraphQL (8090) is accessible"
    else
        echo -e "${YELLOW}[!]${NC} Hasura GraphQL (8090) is not accessible"
    fi
    
    if nc -zv 192.168.20.20 8080 2>&1 | grep -q 'succeeded'; then
        echo -e "${GREEN}[✓]${NC} CitrineOS API (8080) is accessible"
    else
        echo -e "${YELLOW}[!]${NC} CitrineOS API (8080) is not accessible"
    fi
else
    echo -e "${RED}[✗]${NC} CitrineOS is NOT reachable!"
    echo -e "${YELLOW}    Make sure firewall rules allow traffic to 192.168.20.0/24${NC}"
fi

# Build and start containers
echo -e "${GREEN}[4/5]${NC} Building and starting containers..."
docker compose down 2>/dev/null || true
docker compose up -d --build

# Wait for service to be healthy
echo -e "${GREEN}[5/5]${NC} Waiting for service to start..."
sleep 5

# Check if service is running
if curl -s http://localhost:80 > /dev/null; then
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              Deployment Successful!                           ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "Web Portal URL:     ${GREEN}http://192.168.125.100${NC}"
    echo ""
    echo -e "${YELLOW}Test Credentials:${NC}"
    echo "  Admin: admin@ecocharge.local / admin123"
    echo "  User:  john.doe@example.com / password123"
    echo ""
    echo -e "${YELLOW}Vulnerable Endpoints:${NC}"
    echo "  - /robots.txt"
    echo "  - /.git/config"
    echo "  - /js/config.js"
    echo "  - /api/internal/config"
    echo "  - /api/user/<id> (IDOR)"
    echo "  - /api/stations/search?location= (SQLi)"
    echo "  - /debug"
    echo ""
else
    echo -e "${RED}[✗] Service failed to start!${NC}"
    echo "Check logs with: docker compose logs"
    exit 1
fi

# Show container status
echo -e "${YELLOW}Container Status:${NC}"
docker compose ps

echo ""
echo "Use 'docker compose logs -f' to view logs"
echo "Use 'docker compose down' to stop the service"
