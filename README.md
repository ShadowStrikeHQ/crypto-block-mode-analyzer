# crypto-block-mode-analyzer
Analyzes ciphertext to determine the likely block cipher mode (e.g., ECB, CBC, CTR) used for encryption without requiring the key. Useful for cryptanalysis and identifying potential vulnerabilities in custom crypto implementations. Performs statistical analysis of block repetitions and other characteristic features. - Focused on Basic cryptographic operations

## Install
`git clone https://github.com/ShadowStrikeHQ/crypto-block-mode-analyzer`

## Usage
`./crypto-block-mode-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `--block_size`: No description provided
- `--threshold`: No description provided
- `--sample_size`: No description provided
- `--enable_ctr_test`: Enable statistical tests for CTR mode, which is time intensive.

## License
Copyright (c) ShadowStrikeHQ
