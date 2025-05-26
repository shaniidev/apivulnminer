#!/usr/bin/env python3
"""
Setup script for APIVulnMiner
Allows installation as a system-wide command
"""

from setuptools import setup, find_packages
import os

# Read the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="apivulnminer",
    version="1.0.0",
    author="Shani",
    author_email="contact@shaniidev.com",
    description="Advanced API Vulnerability Scanner with AI-powered endpoint discovery",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/shaniidev/apivulnminer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "apivulnminer=apivulnminer:main",
        ],
    },
    keywords=[
        "api", "security", "vulnerability", "scanner", "penetration-testing",
        "bug-bounty", "owasp", "cybersecurity", "ethical-hacking", "automation"
    ],
    project_urls={
        "Bug Reports": "https://github.com/shaniidev/apivulnminer/issues",
        "Source": "https://github.com/shaniidev/apivulnminer",
        "Documentation": "https://github.com/shaniidev/apivulnminer#readme",
        "LinkedIn": "https://linkedin.com/in/shaniii",
    },
    include_package_data=True,
    zip_safe=False,
) 