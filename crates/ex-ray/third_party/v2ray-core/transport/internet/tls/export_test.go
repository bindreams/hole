package tls

// DeleteECHCacheEntryForTest removes a domain from the process-wide ECH DoH cache
// so an external-package test that triggered a RefreshECHCache write can clean up
// and not leak into sibling tests.
func DeleteECHCacheEntryForTest(domain string) {
	mutex.Lock()
	defer mutex.Unlock()
	delete(dnsCache, domain)
}
