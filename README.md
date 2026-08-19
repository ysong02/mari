# Related work CRAFT node and gateway

This repo is for the comparison between SALSA and related work.
  
## Project Structure

```
repo/
├── app/                    # Example applications and tests
│   ├── 03app_gateway/     # Gateway implementation example
│   ├── 03app_node/        # Node implementation example
│   └── ...                # Various test applications
├── drv/                   # Hardware drivers
├── mari/                  # Core protocol implementation
└── nRF/                   # Nordic Semiconductor SDK files
```


## Hardware Support

- nRF52833
- nRF52840
- nRF5340

## Development Environment

The project includes configuration files for:
- Segger Embedded Studio (`.emProject` files)
- Code formatting (`.clang-format` file, please use `clang-format` version 15)
- Git hooks (`.pre-commit-config.yaml`)

## License

This project is licensed under the terms included in the LICENSE file.

## Publications

The network that we operate on:
- Fedrecheski et al., "Mari: Connecting Large Scale Robot Swarms over BLE using TSCH with Multiple Independent Gateways", CrystalFreeIoT Workshop 2025 [Forthcoming]
