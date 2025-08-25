# IDA Mask Plugin

A professional IDA Pro plugin for binary pattern analysis and generation, featuring ARM64 assembly-to-pattern conversion capabilities.

## Features

### **Search by Pattern:Mask**
Search through loaded binaries using byte patterns with wildcard support for flexible binary analysis.

### **Create Pattern:Mask**  
Generate precise byte patterns and masks from ARM64 assembly templates, powered by the `arm64-mask-gen` engine.

## 📦 Installation

### Step 1: Install the Plugin
Copy the plugin file to your IDA Pro plugins directory:

```bash
cp ida_mask_plugin.py ~/.idapro/plugins/
```

### Step 2: Install Dependencies
Install the required Python packages using the provided requirements file:

```bash
pip install -r requirements.txt
```

Or install individually:
```bash
pip install arm64-mask-gen-py capstone
```

> **Note**: For IDA Pro's embedded Python, you may need to use the specific Python interpreter that IDA uses.

## 🚀 Usage

### Accessing the Plugin
1. Launch IDA Pro and load your target binary
2. Navigate to **Edit → Plugins → IDA Mask Plugin**
3. Select your desired operation

### Pattern Search
Enter a hex pattern with mask to search through the binary:
- **Pattern**: `48 89 4C 24 08`
- **Mask**: `FF FF FF FF FF` (exact match) or `FF FF FF FF 00` (wildcard last byte)

### Pattern Generation
Input ARM64 assembly templates to generate corresponding patterns:

**Example:**
```
Template : MOV X3, #?
Pattern  : 030080d2
Mask     : 1f00e0ff
COMBINED : 030080d2:1f00e0ff
```


## Requirements

- **IDA Pro** 9.0+ (tested)
- **Python** 3.7+ (bundled with IDA Pro)
- **Dependencies** (auto-installed via requirements.txt):
  - `arm64-mask-gen-py`: ARM64 pattern generation engine
  - `capstone`: Disassembly framework

## Advanced Configuration

### Custom Python Environment
If IDA Pro uses a different Python interpreter, install dependencies directly:

```bash
/path/to/ida/python -m pip install arm64-mask-gen-py capstone
```

### Building from Source
For development or custom builds, use the PyO3 wrapper:

```bash
git clone https://github.com/xliee/arm64-mask-gen-py-wrapper
cd arm64-mask-gen-py-wrapper
maturin develop --release
```

## Related Projects

- **Core Library**: [arm64-mask-gen](https://github.com/xliee/arm64-mask-gen) - Rust-based pattern generation engine
- **Python Wrapper**: [arm64-mask-gen-py-wrapper](https://github.com/xliee/arm64-mask-gen-py-wrapper) - PyO3 bindings
- **PyPI Package**: [arm64-mask-gen-py](https://pypi.org/project/arm64-mask-gen-py/) - Published Python wheel

## 📝 License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

