package version

// values get filled in at build time via go build args

// Commit set to the short hash of the commit
var Commit string

// Version gets passed in from the makefile
var Version string

// Buildtime was the time the binary was compiled
var Buildtime string
