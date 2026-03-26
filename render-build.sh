#!/usr/bin/env bash
# exit on error
set -o errexit

pip install -r requirements.txt

# This installs the Tesseract binary on Render's Linux environment
apt-get update && apt-get install -y tesseract-ocr