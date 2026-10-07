package app

// restrictUmask is a no-op on Windows; files inherit the per-user profile's
// ACLs.
func restrictUmask() {}
