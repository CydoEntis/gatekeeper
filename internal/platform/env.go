package platform

// GOOSWindows is runtime.GOOS on Windows.
//
// It is exported and named because more than one package compares against it, and
// a typo in such a comparison fails silently: the branch simply never runs, the
// tests still pass on Linux, and the code looks correct. Sharing one name is what
// makes that impossible.
const GOOSWindows = "windows"
