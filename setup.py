from setuptools import setup, find_packages

setup(
    name="nids-lite",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'flask',
        'python-nmap',
        'scapy',
        'requests',
        'python-dotenv',
        'flask-sqlalchemy',
        'python-whois',
        'cryptography',
        'pytest',
        'gunicorn'
    ],
    entry_points={
        'console_scripts': [
            'nids=lansecmon:main',
        ],
    },
    author="Your Name",
    description="Network Intrusion Detection System with AI-powered analysis",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/nids",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
)
