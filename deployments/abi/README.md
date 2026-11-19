# Contract ABI Schemas

Generated JSON schemas for all public Soroban contract entrypoints via:

```bash
stellar contract build
./scripts/generate-abis.sh
```

Each `<contract>.abi.json` file is extracted from `stellar contract inspect --wasm ... --output json`.
