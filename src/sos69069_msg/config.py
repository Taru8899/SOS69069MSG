"""Global configuration for the SOS 69069 client."""

# Official SOS 69069 contract (Ethereum mainnet)
CONTRACT_ADDRESS = "0x7373DBC24Dcd785896E8Ac3d5372c6ced9B75a8A"

# EIP-712 domain (must match the contract exactly)
EIP712_NAME = "69069"
EIP712_VERSION = "1"

# Ethereum mainnet. The chain id is part of the signed domain: signing with
# the wrong value makes every record revert with InvalidSignature().
CHAIN_ID = 1

# Hard limit from the contract (bytes of the UTF-8 metadata string)
MAX_METADATA_LENGTH = 64
