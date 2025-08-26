# sui-package

A Sui Move smart contract for TEE (Trusted Execution Environment) access control and encrypted file management.

## Prerequisites

1. **Install Sui CLI**
   ```bash
   cargo install --locked --git https://github.com/MystenLabs/sui.git --branch mainnet sui
   ```

2. **Import Your Wallet** (with SUI tokens)
   ```bash
   sui client import [YOUR_PRIVATE_KEY] ed25519
   ```

3. **Configure Networks**
   ```bash
   # Add testnet
   sui client new-env --alias testnet --rpc https://fullnode.testnet.sui.io:443
   
   # Add mainnet
   sui client new-env --alias mainnet --rpc https://fullnode.mainnet.sui.io:443
   ```

## Deployment

### Testnet Deployment

1. **Switch to testnet and get test tokens**
   ```bash
   sui client switch --env testnet
   sui client faucet
   ```

2. **Deploy contract**
   ```bash
   cd contract
   sui move build
   sui client publish --gas-budget 100000000
   ```

3. **Save the Package ID** from the deployment output

### Mainnet Deployment

1. **Switch to mainnet and verify balance**
   ```bash
   sui client switch --env mainnet
   sui client balance  # Ensure you have sufficient SUI
   ```

2. **Deploy contract**
   ```bash
   cd contract
   sui move build
   sui client publish --gas-budget 100000000
   ```

3. **Save the Package ID** from the deployment output

## Verification

- **Check deployment**: Visit [Sui Explorer](https://suiexplorer.com) and search for your Package ID
- **Testnet Explorer**: https://suiexplorer.com/?network=testnet
- **Mainnet Explorer**: https://suiexplorer.com/?network=mainnet

## Troubleshooting

- **Insufficient gas**: Reduce gas budget (e.g., `--gas-budget 50000000`)
- **No funds**: Import wallet with SUI tokens or use `sui client faucet` on testnet
- **Check active wallet**: `sui client active-address && sui client balance`