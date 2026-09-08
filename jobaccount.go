package main

import "os/user"

// jobAccount is what this host runs commands as, for reporting.
//
// The name is never empty in what is sent: jobUser.Name is empty when commands
// run as the agent itself, and that is precisely the case an operator needs to
// see — reporting nothing there would make the risky configuration the one that
// says least. So the agent's own account is resolved and reported instead, with
// isolated=false to say which of the two it is.
//
// A uid is the fallback when the account has no passwd entry, which is ordinary
// inside a container. It is worse to read than a name and far better than
// nothing.
func jobAccount(who jobUser) (name string, isolated bool) {
	if who.separate() {
		return who.Name, true
	}
	return currentAccount(), false
}

func currentAccount() string {
	if u, err := user.Current(); err == nil {
		if u.Username != "" {
			return u.Username
		}
		return "uid " + u.Uid
	}
	return "unknown"
}
