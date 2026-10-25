// Package service implements the use cases of the service: creating, reading and
// replacing a threat. It applies the rules of the domain, assigns the timestamps
// and delegates persistence to a Repository, an interface declared here and
// satisfied by the storage layer.
package service
