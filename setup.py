#!/usr/bin/env python3
"""
setup.py
========
Package configuration for k8s-sec - Kubernetes Security Assessment Platform.
"""

from setuptools import setup, find_packages
from pathlib import Path

ROOT = Path(__file__).parent

setup(
    name="k8s-sec",
    version="2.0.0",
    description="Kubernetes ML Security Assessment Platform & Admission Controller",
    long_description=(ROOT / "README.md").read_text(encoding="utf-8") if (ROOT / "README.md").exists() else "",
    long_description_content_type="text/markdown",
    author="Google DeepMind Advanced Agentic Coding",
    python_requires=">=3.9",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    entry_points={
        "console_scripts": [
            "k8s-sec = cli.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
)
