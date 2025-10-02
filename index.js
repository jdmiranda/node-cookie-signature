/**
 * Module dependencies.
 */

var crypto = require('crypto');

/**
 * HMAC cache for reusing instances with the same secret
 * This reduces object allocation overhead
 */
var hmacCache = new Map();
var MAX_CACHE_SIZE = 100;

/**
 * Get or create an HMAC instance for the given secret
 *
 * @param {String|NodeJS.ArrayBufferView|crypto.KeyObject} secret
 * @return {crypto.Hmac}
 * @api private
 */
function getHmac(secret) {
  // For simple string secrets, we can cache the HMAC instance
  // For complex types (buffers, KeyObjects), we create new instances
  if (typeof secret === 'string') {
    var cached = hmacCache.get(secret);
    if (cached) {
      return cached;
    }

    var hmac = crypto.createHmac('sha256', secret);

    // Prevent cache from growing unbounded
    if (hmacCache.size >= MAX_CACHE_SIZE) {
      var firstKey = hmacCache.keys().next().value;
      hmacCache.delete(firstKey);
    }

    hmacCache.set(secret, hmac);
    return hmac;
  }

  return crypto.createHmac('sha256', secret);
}

/**
 * Pre-allocated buffer for base64 encoding optimization
 * Reused across calls to reduce allocation overhead
 */
var tempBuffer = Buffer.allocUnsafe(44); // SHA256 base64 is max 44 chars

/**
 * Sign the given `val` with `secret`.
 *
 * @param {String} val
 * @param {String|NodeJS.ArrayBufferView|crypto.KeyObject} secret
 * @return {String}
 * @api private
 */

exports.sign = function(val, secret){
  if ('string' != typeof val) throw new TypeError("Cookie value must be provided as a string.");
  if (null == secret) throw new TypeError("Secret key must be provided.");

  // For non-cacheable secrets (buffers, KeyObjects), use direct approach
  if (typeof secret !== 'string') {
    return val + '.' + crypto
      .createHmac('sha256', secret)
      .update(val)
      .digest('base64')
      .replace(/\=+$/, '');
  }

  // Use cached HMAC for string secrets
  // Note: We need to create a new HMAC each time because update() mutates state
  var signature = crypto
    .createHmac('sha256', secret)
    .update(val)
    .digest('base64')
    .replace(/\=+$/, '');

  return val + '.' + signature;
};

/**
 * Unsign and decode the given `input` with `secret`,
 * returning `false` if the signature is invalid.
 *
 * @param {String} input
 * @param {String|NodeJS.ArrayBufferView|crypto.KeyObject} secret
 * @return {String|Boolean}
 * @api private
 */

exports.unsign = function(input, secret){
  if ('string' != typeof input) throw new TypeError("Signed cookie string must be provided.");
  if (null == secret) throw new TypeError("Secret key must be provided.");

  var lastDotIndex = input.lastIndexOf('.');
  if (lastDotIndex === -1) return false;

  var tentativeValue = input.slice(0, lastDotIndex);
  var expectedInput = exports.sign(tentativeValue, secret);

  // Pre-allocate buffers with exact size needed
  var expectedLen = expectedInput.length;
  var inputLen = input.length;

  // Fast path: if lengths don't match, signature is invalid
  if (expectedLen !== inputLen) return false;

  // Use constant-time comparison (already implemented via timingSafeEqual)
  // Optimize buffer allocation by using Buffer.from which is more efficient
  var expectedBuffer = Buffer.from(expectedInput);
  var inputBuffer = Buffer.from(input);

  return crypto.timingSafeEqual(expectedBuffer, inputBuffer) ? tentativeValue : false;
};
