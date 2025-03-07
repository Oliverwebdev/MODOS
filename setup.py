from setuptools import setup, find_packages

setup(
    name="dos-framework",
    version="1.0.0",
    description="Fortgeschrittenes DoS-Test-Framework für autorisierte Sicherheits- und Forschungstests.",
    author="Dein Name",
    packages=find_packages("src"),
    package_dir={"": "src"},
    install_requires=[
        "aiohttp",
        "fastapi",
        "uvicorn",
        "colorama",
        "numpy",
        "psutil",
        "scapy",
        "requests",
        # weitere Abhängigkeiten nach Bedarf
    ],
    entry_points={
        "console_scripts": [
            "dos-framework = main:main",
        ],
    },
)
