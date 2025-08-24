# IDA Mask Plugin

Python plugin for IDA Pro that provides pattern search and generation functionality.

## Features

- **Search by pattern:mask**: Search binary for byte patterns with wildcards
- **Create pattern:mask**: Generate patterns from assembly code snippets

## Structure

- `ida_mask_plugin.py`: Main Python plugin implementation

## Installation

### Method 1: User Plugins Directory (Recommended)
Copy the plugin to your user plugins directory:

```bash
cp ida_mask_plugin.py ~/.idapro/plugins/
```

## Usage

1. Start IDA Pro and load a binary
2. Navigate to `Edit -> Plugins -> IDA Mask Plugin`
3. Choose either:
   - **Search by pattern:mask**: Enter hex pattern and mask (e.g., `48894c24?8:ffffffff?f`)
   - **Create pattern:mask**: Enter assembly code to generate a pattern

Note: The `Create pattern:mask` action uses an external Python extension [`arm64_mask_gen_py`](https://github.com/xliee/arm64-mask-gen-py-wrapper) (PyO3 wrapper around the [`arm64-mask-gen`](https://github.com/xliee/arm64-mask-gen) Rust crate). To enable pattern generation from assembly you must build and install the wrapper:

1. Build the wrapper for the Python interpreter used by IDA:

```bash
   maturin develop --release
```

2. Restart IDA so the extension can be imported by the plugin.

If the wrapper is not installed, the plugin will show the assembly input and a warning.

## Requirements

- IDA Pro (tested with version 9.0+)
- Python 3.x (included with IDA Pro)

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.