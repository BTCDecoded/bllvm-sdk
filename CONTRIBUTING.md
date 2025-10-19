# Contributing to developer-sdk

Thank you for your interest in contributing to developer-sdk! This document contains repo-specific guidelines. See the [BTCDecoded Contribution Guide](https://github.com/BTCDecoded/.github/blob/main/CONTRIBUTING.md) for general guidelines.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/BTCDecoded/developer-sdk.git
cd developer-sdk

# Run tests
cargo test

# Run benchmarks
cargo bench

# Check formatting
cargo fmt --check

# Check clippy
cargo clippy --all-targets --all-features
```

## Contribution Areas

### High Priority
- **Governance crypto primitives**: Key generation, signing, verification
- **Multisig operations**: Threshold validation and signature collection
- **CLI tools**: Command-line interfaces for maintainer operations
- **Testing**: Comprehensive test coverage for all crypto operations

### Future Areas
- **Node composition**: Declarative node building from modules
- **Module interfaces**: Standardized module trait definitions
- **Economic integration**: Merge mining revenue model

## Code Standards

### Governance Crypto
- All cryptographic operations must have 100% test coverage
- Use Bitcoin-compatible standards for message signing
- Pin all dependencies to exact versions
- Document security boundaries clearly

### CLI Tools
- Follow standard Unix conventions for command-line interfaces
- Provide clear error messages and usage examples
- Support both JSON and human-readable output formats

### Testing
- Unit tests for all public APIs
- Integration tests for complete workflows
- Property-based testing for cryptographic operations
- Benchmark tests for performance-critical paths

## Pull Request Process

1. **Fork and branch**: Create a feature branch from main
2. **Implement**: Follow the code standards above
3. **Test**: Ensure all tests pass and coverage is maintained
4. **Document**: Update documentation for any API changes
5. **Submit**: Create a pull request with a clear description

## Security Considerations

- Never commit private keys or sensitive data
- All cryptographic changes require security review
- Follow the security boundaries defined in SECURITY.md
- Report security issues through the proper channels

## Questions?

Feel free to open an issue for questions about contributing or the codebase.




