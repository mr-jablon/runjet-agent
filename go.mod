// The agent is its own module so it can be released on its own schedule.
//
// It has no dependencies beyond the standard library, which is not an accident:
// this binary is copied onto machines nobody at Runjet can reach, and every
// dependency it grew would be one more thing an operator has to trust and one
// more reason for it to stop building on an older toolchain.
module github.com/mr-jablon/runjet-agent

go 1.25.0
