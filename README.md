# go-logging

A logging library for Go with utilities for encryption, events, context, deepcopy, and more.

## Directory Structure

- `aes.go`: AES encryption/decryption, padding/unpadding.
- `const.go`: Common constants.
- `context.go`: Context handling for logging.
- `deepcopy.go`: Deep copy struct/object.
- `encrypt.go`: Other encryption functions besides AES.
- `event.go`: Logging event definitions.
- `log.go`: Main logging functions.
- `logger.go`: Logger struct, interface, config definitions.
- `utils.go`: Common utility functions.

## Usage

```go
import "github.com/your-org/go-logging/logger"

log := logger.NewLogger()
log.Info("Hello world")
```

## AES Encryption
```go
encrypted, err := logger.Encrypt("mytext", "yourhexkey...")
decrypted, err := logger.Decrypt(encrypted, "yourhexkey...")
```

## Contribution
- Fork, create a branch, and submit a PR.
- Write tests for new features.
