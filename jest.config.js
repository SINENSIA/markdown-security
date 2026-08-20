// sanitize-html >=2.17.6 depends on htmlparser2 >=12, an ESM-only package
// (along with its domhandler/domutils/dom-serializer/domelementtype/entities
// chain). Jest's CommonJS runtime cannot evaluate `import` syntax, so transpile
// those packages to CommonJS with @swc/jest. Node >=22.12.0 handles them
// natively at runtime; this transform only exists for the test runner.
module.exports = {
  transform: {
    '^.+\\.[cm]?js$': [
      '@swc/jest',
      { jsc: { target: 'es2022' }, module: { type: 'commonjs' } },
    ],
  },
  transformIgnorePatterns: [
    '/node_modules/(?!(htmlparser2|domhandler|domutils|dom-serializer|domelementtype|entities)/)',
  ],
};
