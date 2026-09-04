// The one setup file, and it must stay nearly free for the node suite.
//
// `setupFiles` is global — Vitest has no per-environment setup list — so this
// module is imported once per test file, including the 111 main-process files
// that will never render anything. It therefore does no work and pulls in no
// dependency until it has established that it is running inside a DOM.
// Importing @testing-library/react here unconditionally would put react-dom in
// front of every sqlite test in the suite.
//
// A renderer test declares `// @vitest-environment jsdom` at the top of the
// file; that is what makes `window` exist by the time this runs, and that is
// the only signal this file uses.
if (typeof window !== 'undefined') {
  await import('./renderer')
}

// Top-level `await` is only legal in a module, and a file with no import or
// export is a script. The dynamic import above does not count as one.
export {}
