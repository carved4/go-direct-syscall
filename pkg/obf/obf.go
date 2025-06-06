// Package obf provides string hashing and obfuscation utilities.
package obf

// DBJ2HashStr calculates a hash for a string using the DBJ2 algorithm.
func DBJ2HashStr(s string) uint32 {
	return DBJ2Hash([]byte(s))
}

// DBJ2Hash calculates a hash for a byte slice using the DBJ2 algorithm.
func DBJ2Hash(buffer []byte) uint32 {
	hash := uint32(5381)
	
	for _, b := range buffer {
		if b == 0 {
			continue
		}
		
		// Convert lowercase to uppercase (same as in the Rust version)
		if b >= 'a' {
			b -= 0x20
		}
		
		// This is equivalent to: hash = ((hash << 5) + hash) + uint32(b)
		// The wrapping_add in Rust is naturally handled in Go's uint32
		hash = ((hash << 5) + hash) + uint32(b)
	}
	
	return hash
}

// HashCache is a map to store precomputed hashes for performance
var HashCache = make(map[string]uint32)

// GetHash returns the hash for a string, using the cache if available
func GetHash(s string) uint32 {
	if hash, ok := HashCache[s]; ok {
		return hash
	}
	
	hash := DBJ2HashStr(s)
	HashCache[s] = hash
	return hash
}
