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
