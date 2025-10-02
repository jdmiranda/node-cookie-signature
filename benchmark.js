/**
 * Performance benchmark for cookie-signature optimization
 */

var cookie = require('./index.js');

function benchmark(name, fn, iterations) {
  // Warm-up
  for (var i = 0; i < 1000; i++) {
    fn();
  }

  // Actual benchmark
  var start = process.hrtime.bigint();
  for (var i = 0; i < iterations; i++) {
    fn();
  }
  var end = process.hrtime.bigint();

  var elapsed = Number(end - start) / 1000000; // Convert to milliseconds
  var opsPerSec = (iterations / elapsed) * 1000;

  console.log(name);
  console.log('  Total time: ' + elapsed.toFixed(2) + 'ms');
  console.log('  Operations: ' + iterations);
  console.log('  Ops/sec: ' + opsPerSec.toFixed(0));
  console.log('  Avg time per op: ' + (elapsed / iterations).toFixed(4) + 'ms');
  console.log('');

  return {
    name: name,
    totalTime: elapsed,
    operations: iterations,
    opsPerSec: opsPerSec,
    avgTime: elapsed / iterations
  };
}

console.log('Cookie Signature Performance Benchmarks');
console.log('=======================================\n');

var iterations = 100000;
var secret = 'my-secret-key';
var value = 'user-id-12345';
var signedValue = cookie.sign(value, secret);

// Benchmark signing
var signResults = benchmark('Sign operation', function() {
  cookie.sign(value, secret);
}, iterations);

// Benchmark unsigning (valid)
var unsignValidResults = benchmark('Unsign operation (valid)', function() {
  cookie.unsign(signedValue, secret);
}, iterations);

// Benchmark unsigning (invalid)
var invalidSignedValue = signedValue + 'tampered';
var unsignInvalidResults = benchmark('Unsign operation (invalid)', function() {
  cookie.unsign(invalidSignedValue, secret);
}, iterations);

// Test with different value sizes
var smallValue = 'a';
var mediumValue = 'a'.repeat(100);
var largeValue = 'a'.repeat(1000);

var smallSignResults = benchmark('Sign (small value: 1 char)', function() {
  cookie.sign(smallValue, secret);
}, iterations);

var mediumSignResults = benchmark('Sign (medium value: 100 chars)', function() {
  cookie.sign(mediumValue, secret);
}, iterations);

var largeSignResults = benchmark('Sign (large value: 1000 chars)', function() {
  cookie.sign(largeValue, secret);
}, iterations);

// Test with buffer secret
var bufferSecret = Buffer.from('my-secret-key');
var bufferSignResults = benchmark('Sign with Buffer secret', function() {
  cookie.sign(value, bufferSecret);
}, iterations);

// Summary
console.log('Summary');
console.log('=======');
console.log('');
console.log('Basic Operations:');
console.log('  Sign:                    ' + signResults.opsPerSec.toFixed(0) + ' ops/sec');
console.log('  Unsign (valid):          ' + unsignValidResults.opsPerSec.toFixed(0) + ' ops/sec');
console.log('  Unsign (invalid):        ' + unsignInvalidResults.opsPerSec.toFixed(0) + ' ops/sec');
console.log('');
console.log('Value Size Impact:');
console.log('  Small (1 char):          ' + smallSignResults.opsPerSec.toFixed(0) + ' ops/sec');
console.log('  Medium (100 chars):      ' + mediumSignResults.opsPerSec.toFixed(0) + ' ops/sec');
console.log('  Large (1000 chars):      ' + largeSignResults.opsPerSec.toFixed(0) + ' ops/sec');
console.log('');
console.log('Secret Type Impact:');
console.log('  String secret:           ' + signResults.opsPerSec.toFixed(0) + ' ops/sec');
console.log('  Buffer secret:           ' + bufferSignResults.opsPerSec.toFixed(0) + ' ops/sec');
console.log('');

// Export results for comparison
module.exports = {
  sign: signResults,
  unsignValid: unsignValidResults,
  unsignInvalid: unsignInvalidResults,
  smallSign: smallSignResults,
  mediumSign: mediumSignResults,
  largeSign: largeSignResults,
  bufferSign: bufferSignResults
};
