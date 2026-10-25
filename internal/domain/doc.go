// Package domain defines the model of the service: a threat, identified by the MD5
// hash of a file, its enumerations and its invariants, together with the errors
// that the other layers exchange. The package imports no other package of the
// project, so its rules hold regardless of the transport and of the storage.
package domain
