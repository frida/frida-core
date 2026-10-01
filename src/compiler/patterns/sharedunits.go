package patterns

import (
	"crypto/sha256"
	"encoding/hex"
)

type sharedUnit struct {
	key      string
	source   Source
	incoming macros
	registry *unitRegistry
	compiled bool
	module   *Module
}

type unitRegistry struct {
	resolver Resolver
	byKey    map[string]*sharedUnit
}

type origin struct {
	unit *sharedUnit
	name string
}

func (s *sharedUnit) library() *Module {
	if !s.compiled {
		s.compiled = true
		s.module, _ = compileUnit(s.source, s.incoming, s.registry)
	}
	return s.module
}

func (s *sharedUnit) path() string {
	digest := sha256.Sum256([]byte(s.key))
	return "/unit-" + hex.EncodeToString(digest[:8]) + ".js"
}
