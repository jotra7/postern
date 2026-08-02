package bundle

// OpenInner exposes every check Open runs after the seal, so the fuzz target
// can drive the record parser directly on arbitrary bytes. Going through Open
// would mean sealing each input first, which costs two scalar multiplications
// per execution and makes the target non-deterministic — a crasher found that
// way would not reproduce.
//
// This file has the _test.go suffix, so the toolchain compiles it only into
// the test binary. OpenInner never exists in a production build: unsealing is
// not optional, and there is no shipped entry point that skips it.
func OpenInner(inner []byte, trustedSigners [][32]byte, want AcceptCriteria) (*Contents, error) {
	return openInner(inner, trustedSigners, want)
}
