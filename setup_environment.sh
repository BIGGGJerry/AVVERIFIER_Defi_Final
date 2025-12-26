#!/bin/bash

# AVVERIFIER Environment Setup Script
# For reproducing "All Your Tokens are Belong to Us" paper experiments

set -e

echo "=========================================="
echo "AVVERIFIER Environment Setup"
echo "=========================================="

# Check Python version
echo ""
echo "Checking Python version..."
python3 --version

# Create virtual environment
echo ""
echo "Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "Virtual environment created."
else
    echo "Virtual environment already exists."
fi

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
pip install mythril z3-solver web3 tqdm requests

# Verify installations
echo ""
echo "Verifying installations..."
python3 -c "import mythril; print('✓ mythril installed')"
python3 -c "import z3; print('✓ z3-solver installed')"
python3 -c "import web3; print('✓ web3 installed')"
python3 -c "import tqdm; print('✓ tqdm installed')"
python3 -c "import requests; print('✓ requests installed')"

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "To use the environment, run:"
echo "  source venv/bin/activate"
echo ""
echo "Tools available:"
echo "  1. AVVERIFIER (solstatic.py & stack.py)"
echo "  2. Mythril Modify (cp_mythril.py)"
echo "  3. Ethainter Detector (requires Gigahorse)"
echo ""
