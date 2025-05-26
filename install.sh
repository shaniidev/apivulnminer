#!/bin/bash

# APIVulnMiner Installation Script
# Makes APIVulnMiner available system-wide like nmap

set -e

echo "🎯 APIVulnMiner Installation Script"
echo "======================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root for system-wide installation
if [[ $EUID -eq 0 ]]; then
    INSTALL_TYPE="system"
    echo -e "${GREEN}✓${NC} Running as root - Installing system-wide"
else
    INSTALL_TYPE="user"
    echo -e "${YELLOW}!${NC} Running as user - Installing for current user only"
    echo -e "  ${BLUE}Tip:${NC} Run with sudo for system-wide installation"
fi

echo ""

# Check Python version
echo -e "${BLUE}[1/6]${NC} Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION found"
    
    # Check if version is >= 3.8
    if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 8) else 1)'; then
        echo -e "${GREEN}✓${NC} Python version is compatible (>= 3.8)"
    else
        echo -e "${RED}✗${NC} Python 3.8+ required. Current version: $PYTHON_VERSION"
        exit 1
    fi
else
    echo -e "${RED}✗${NC} Python 3 not found. Please install Python 3.8+"
    exit 1
fi

echo ""

# Check pip
echo -e "${BLUE}[2/6]${NC} Checking pip..."
if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}✓${NC} pip3 found"
    PIP_CMD="pip3"
elif command -v pip &> /dev/null; then
    echo -e "${GREEN}✓${NC} pip found"
    PIP_CMD="pip"
else
    echo -e "${RED}✗${NC} pip not found. Please install pip"
    exit 1
fi

echo ""

# Install dependencies
echo -e "${BLUE}[3/6]${NC} Installing dependencies..."
if [[ $INSTALL_TYPE == "system" ]]; then
    $PIP_CMD install -r requirements.txt
else
    $PIP_CMD install --user -r requirements.txt
fi
echo -e "${GREEN}✓${NC} Dependencies installed"

echo ""

# Install APIVulnMiner
echo -e "${BLUE}[4/6]${NC} Installing APIVulnMiner..."
if [[ $INSTALL_TYPE == "system" ]]; then
    $PIP_CMD install -e .
else
    $PIP_CMD install --user -e .
fi
echo -e "${GREEN}✓${NC} APIVulnMiner installed"

echo ""

# Check installation
echo -e "${BLUE}[5/6]${NC} Verifying installation..."
if command -v apivulnminer &> /dev/null; then
    echo -e "${GREEN}✓${NC} APIVulnMiner command is available"
    
    # Test the command
    if apivulnminer --help &> /dev/null; then
        echo -e "${GREEN}✓${NC} APIVulnMiner is working correctly"
    else
        echo -e "${YELLOW}!${NC} APIVulnMiner installed but may have issues"
    fi
else
    echo -e "${YELLOW}!${NC} APIVulnMiner command not found in PATH"
    
    if [[ $INSTALL_TYPE == "user" ]]; then
        echo -e "  ${BLUE}Note:${NC} You may need to add ~/.local/bin to your PATH"
        echo -e "  ${BLUE}Run:${NC} echo 'export PATH=\$PATH:~/.local/bin' >> ~/.bashrc"
        echo -e "  ${BLUE}Then:${NC} source ~/.bashrc"
    fi
fi

echo ""

# Create symlink for easier access (if system install)
echo -e "${BLUE}[6/6]${NC} Final setup..."
if [[ $INSTALL_TYPE == "system" ]]; then
    # Try to create a symlink in /usr/local/bin
    if [[ -w /usr/local/bin ]]; then
        APIVULNMINER_PATH=$(which apivulnminer 2>/dev/null || echo "")
        if [[ -n "$APIVULNMINER_PATH" && ! -L /usr/local/bin/apivulnminer ]]; then
            ln -sf "$APIVULNMINER_PATH" /usr/local/bin/apivulnminer 2>/dev/null || true
            echo -e "${GREEN}✓${NC} Created symlink in /usr/local/bin"
        fi
    fi
fi

echo -e "${GREEN}✓${NC} Installation complete!"

echo ""
echo "🎉 APIVulnMiner Installation Complete!"
echo "======================================"
echo ""
echo -e "${GREEN}Usage:${NC}"
echo "  apivulnminer -u https://api.example.com"
echo "  apivulnminer -u https://api.example.com -o html"
echo "  apivulnminer --help"
echo ""
echo -e "${BLUE}Examples:${NC}"
echo "  apivulnminer -u https://jsonplaceholder.typicode.com"
echo "  apivulnminer -u https://api.github.com -t 30 -d 0.1"
echo "  apivulnminer -u https://api.example.com -o html -f report.html"
echo ""
echo -e "${YELLOW}Author:${NC} Shani (@shaniidev)"
echo -e "${YELLOW}GitHub:${NC} https://github.com/shaniidev/apivulnminer"
echo -e "${YELLOW}LinkedIn:${NC} https://linkedin.com/in/shaniii"
echo ""
echo -e "${GREEN}Happy Hacking! 🚀${NC}" 