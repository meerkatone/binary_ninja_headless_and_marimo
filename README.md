# Binary-Ninja-Headless-and-Marimo
Using Binary Ninja Headless with Marimo

git clone https://github.com/meerkatone/Binary-Ninja-Headless-and-Marimo.git

## Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

## Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

## Setup venv and Marimo
uv venv venv_marimo --python 3.12

source /venv_marimo/headless/bin/activate

cd Binary-Ninja-Headless-and-Marimo

uv pip install marimo

## Install the Binary Ninja API
- python3 ~/binaryninja/scripts/install_api.py
- python3 /Applications/Binary\ Ninja.app/Contents/Resources/scripts/install_api.py
- Windows (user install): %LOCALAPPDATA%\Vector35\BinaryNinja

## Launch the notebook
marimo edit ./binary_ninja_headless.py

The notebook will ask you to install the required dependencies via uv.
