// Package obf provides string hashing and obfuscation utilities.
package obf

import (
	"sync"
)

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
var hashCacheMutex sync.RWMutex
var collisionDetector = make(map[uint32]string)
var collisionMutex sync.RWMutex

// GetHash returns the hash for a string, using the cache if available
func GetHash(s string) uint32 {
	hashCacheMutex.RLock()
	if hash, ok := HashCache[s]; ok {
		hashCacheMutex.RUnlock()
		return hash
	}
	hashCacheMutex.RUnlock()
	
	hash := DBJ2HashStr(s)
	
	// Store in cache with collision detection
	hashCacheMutex.Lock()
	HashCache[s] = hash
	hashCacheMutex.Unlock()
	
	// Check for hash collisions
	detectHashCollision(hash, s)
	
	return hash
}

// detectHashCollision checks for and logs hash collisions
func detectHashCollision(hash uint32, newString string) {
	collisionMutex.Lock()
	defer collisionMutex.Unlock()
	
	if existingString, exists := collisionDetector[hash]; exists {
		if existingString != newString {
			// Hash collision detected!
			// This is extremely rare with DBJ2 but we should log it
			// In production, you might want to use a different hash or handle this differently
			println("Warning: Hash collision detected!")
			println("  Hash:", hash)
			println("  Existing string:", existingString)
			println("  New string:", newString)
		}
	} else {
		collisionDetector[hash] = newString
	}
}

// FNV1AHash provides an alternative hash algorithm for better collision resistance
func FNV1AHash(buffer []byte) uint32 {
	const (
		fnv1aOffset = 2166136261
		fnv1aPrime  = 16777619
	)
	
	hash := uint32(fnv1aOffset)
	
	for _, b := range buffer {
		if b == 0 {
			continue
		}
		
		// Convert lowercase to uppercase for consistency
		if b >= 'a' {
			b -= 0x20
		}
		
		hash ^= uint32(b)
		hash *= fnv1aPrime
	}
	
	return hash
}

// GetHashWithAlgorithm allows choosing the hash algorithm
func GetHashWithAlgorithm(s string, algorithm string) uint32 {
	switch algorithm {
	case "fnv1a":
		return FNV1AHash([]byte(s))
	case "dbj2":
		fallthrough
	default:
		return DBJ2HashStr(s)
	}
}

// ClearHashCache clears all cached hashes (useful for testing)
func ClearHashCache() {
	hashCacheMutex.Lock()
	defer hashCacheMutex.Unlock()
	
	collisionMutex.Lock()
	defer collisionMutex.Unlock()
	
	HashCache = make(map[string]uint32)
	collisionDetector = make(map[uint32]string)
}

// GetHashCacheStats returns statistics about the hash cache
func GetHashCacheStats() map[string]interface{} {
	hashCacheMutex.RLock()
	defer hashCacheMutex.RUnlock()
	
	collisionMutex.RLock()
	defer collisionMutex.RUnlock()
	
	collisions := 0
	uniqueHashes := len(collisionDetector)
	totalEntries := len(HashCache)
	
	if totalEntries > uniqueHashes {
		collisions = totalEntries - uniqueHashes
	}
	
	return map[string]interface{}{
		"total_entries":  totalEntries,
		"unique_hashes":  uniqueHashes,
		"collisions":     collisions,
		"cache_hit_ratio": 0.0, // Could implement hit counting if needed
	}
}
