from setuptools import setup, find_packages

# バージョン情報を取得
with open("AQE/__init__.py", "r",encoding="utf-8") as f:
    for line in f:
        if line.startswith("__version__"):
            version = line.split("=")[1].strip().strip('"').strip("'")
            break

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="AQE",
    version=version,
    packages=find_packages(),
    install_requires=[
        "cryptography>=36.0.0",
        "pycryptodome>=3.14.0",
        "configparser>=5.3.0",
        "asyncio>=3.4.3",
        "liboqs-python>=0.7.0",

    ],
    author="Meow",
    author_email="example.example.1.mm@icloud.com",
    description="Anti-Quantum Encryption - ポスト量子時代向け暗号ライブラリ",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Lumina-Group/AQE",
    python_requires=">=3.11",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security :: Cryptography :: Post-Quantum",
    ],
    keywords="quantum, encryption, cryptography, post-quantum, security",
)