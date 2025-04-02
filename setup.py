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
        "liboqs-python>=0.7.0", # Open Quantum Safe ライブラリ
    ],
    author="Meow",
    author_email="example.example.1.mm@icloud.com",
    description="Anti-Quantum Encryption - ポスト量子時代向け暗号ライブラリ",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Lumina-Group/AQE",
    python_requires=">=3.7",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security :: Cryptography",
    ],
    keywords="quantum, encryption, cryptography, post-quantum, security",
)
