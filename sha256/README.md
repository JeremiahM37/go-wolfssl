# sha256

wolfCrypt-backed SHA-256 with the same API shape as Go's standard
library `crypto/sha256` package: `Sum256`, `New`, `Size`, `BlockSize`.

Drop-in compatible — callers can swap `import "crypto/sha256"` for
`import "github.com/wolfssl/go-wolfssl/sha256"` with no call-site
changes.
