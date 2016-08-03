'use strict';

var crypto = require('crypto');
var libmime = require('libmime');
var punycode = require('punycode');
var dns = require('dns');
var Q = require('q');
var resolveTxt = Q.denodeify(dns.resolveTxt);

/**
 * @namespace DKIM Signer module
 * @name dkimsign
 */
module.exports.DKIMSign = DKIMSign;
module.exports.DKIMVerify = DKIMVerify;
module.exports.generateDKIMHeader = generateDKIMHeader;
module.exports.sha256 = sha256;
module.exports.KeyFromDNS = KeyFromDNS;

var requiredSigTags = {v: true, a: true, b: true, bh: true, d: true, s: true, h: true};
var validSigTags = {
  v: true, a: true, b: true, bh: true, d: true, s: true, h: true, // required
  c: true, i: true, l: true, q: true, t: true, x: true, z: true // optional
};

var requiredKeyTags = {p: true};
var validKeyTags = {
  p: true, // required
  v: true, g: true, h: true, k: true, n: true, s: true, t: true //optional
};

/**
 * <p>Sign an email with provided DKIM key, uses RSA-SHA256.</p>
 *
 * @memberOf dkimsign
 * @param {String} email Full e-mail source complete with headers and body to sign
 * @param {Object} options DKIM options
 * @param {String} [options.headerFieldNames='from:to:cc:subject'] Header fields to sign
 * @param {String} options.privateKey DKIM private key
 * @param {String} options.domainName Domain name to use for signing (ie: 'domain.com')
 * @param {String} options.keySelector Selector for the DKIM public key (ie. 'dkim' if you have set up a TXT record for 'dkim._domainkey.domain.com')
 *
 * @return {String} Signed DKIM-Signature header field for prepending
 */
function DKIMSign(email, options) {
    options = options || {};
    email = (email || '').toString('utf-8');

    // split email into headers and body
    // empty header section when email begins with CR?LF
    // or when email doesn't contain 2*CR?LF
    var match = email.match(/^\r?\n|(?:\r?\n){2}/),
        headers = match && email.substr(0, match.index) || '',
        body = match && email.substr(match.index + match[0].length) || email;

    // all listed fields from RFC4871 #5.5
    // Some providers do not like Message-Id, Date, Bounces-To and Return-Path
    // fields in DKIM signed data so these are not automatcially included
    var defaultFieldNames = 'From:Sender:Reply-To:Subject:To:' +
        'Cc:MIME-Version:Content-Type:Content-Transfer-Encoding:Content-ID:' +
        'Content-Description:Resent-Date:Resent-From:Resent-Sender:' +
        'Resent-To:Resent-Cc:Resent-Message-ID:In-Reply-To:References:' +
        'List-Id:List-Help:List-Unsubscribe:List-Subscribe:List-Post:' +
        'List-Owner:List-Archive';

    var dkim = generateDKIMHeader(options.domainName, options.keySelector, options.headerFieldNames || defaultFieldNames, headers, body),
        canonicalizedHeaderData = DKIMCanonicalizer.relaxedHeaders(headers, options.headerFieldNames || defaultFieldNames),
        canonicalizedDKIMHeader = DKIMCanonicalizer.relaxedHeaderLine(dkim),
        signer, signature;

    canonicalizedHeaderData.headers += canonicalizedDKIMHeader.key + ':' + canonicalizedDKIMHeader.value;

    signer = crypto.createSign('RSA-SHA256');
    signer.update(canonicalizedHeaderData.headers);
    signature = signer.sign(options.privateKey, 'base64');

    return dkim + signature.replace(/(^.{73}|.{75}(?!\r?\n|\r))/g, '$&\r\n ').trim();
}

/**
 * <p>Perform sanity checks on a DKIM record, fetched from DNS.</p>
 *
 * @memberOf dkimsign
 * @param {String} rec DKIM record
 *
 * @return {Object} Object with `key` {Object} (tag/value from record) and `err` {String} if sanity check fails.
 */
function recSanity(rec) {
  var err, i;
  if (!rec.match(/=/)) {
    return {err: "Invalid DKIM record format"};
  }

  var tags = {};
  rec.split(/\s*;\s*/).map(function(kv) {
    var tmp;
    if (tmp = kv.match(/^(\w+)\s*?=\s*?(.*)$/)) {
      if (validKeyTags[tmp[1]] && tags.hasOwnProperty(tmp[1])) {
        err = "DKIM record contains duplicate tag "+ tmp[1];
      } else {
        tags[tmp[1]] = tmp[2];
      }
    }
  });
  if (err) {
    return {err: err};
  }

  for (var tagName in requiredKeyTags) {
    if (!tags.hasOwnProperty(tagName)) {
      return {err: "DKIM record missing required tag "+ tagName};
    }
  }

  if (tags.v) {
    if (!rec.match(/^v\s*=\s*/)) {
      return {err: "Optional v tag must be first if present in DKIM record"};
    } else if (tags.v != "DKIM1") {
      return {err: "Invalid DKIM record version, use DKIM1"};
    }
  }

  // TODO: support for g tag, interacts with i tag

  if (tags.h) {
    if (tags.h != "sha1" && tags.h != "sha256") {
      return {err: "DKIM record has invalid hashing algorithm"};
    }
  }

  if (tags.k) {
    if (tags.k != "rsa") {
      return {err: "DKIM record has invalid key type"};
    }
  }

  if (tags.p == "") {
    return {err: "DKIM record has been revoked"};
  }

  if (tags.s) {
    if (tags.s != "*" && tags.s != "email") {
      return {err: "DKIM record has invalid service type"};
    }
  }

  // TODO: support for t tag; colon-separated list of flags

  return {rec: tags};
}

/**
 * <p>Perform sanity checks on a DKIM signature, sent with a message.</p>
 *
 * @memberOf dkimsign
 * @param {String} sig DKIM-Signature header value
 *
 * @return {Object} Object with `sigs` {Object} (tag/value from signature) and `err` {String} if sanity check fails.
 */
function sigSanity(sig) {
  var err, i;
  if (!sig.match(/;/)) {
    return {err: "Invalid DKIM-Signature format"};
  }

  if (!sig.match(/^v\s*=\s*1\s*;/)) {
    return {err: "DKIM-Signature must start with v tag"};
  }

  var tags = {};
  sig.split(/\s*;\s*/).map(function(kv) {
    var tmp;
    if (tmp = kv.match(/^(\w+)\s*?=\s*?(.*)$/)) {
      if (validSigTags[tmp[1]] && tags.hasOwnProperty(tmp[1])) {
        err = "DKIM-Signature contains duplicate tag "+ tmp[1];
      } else {
        tags[tmp[1]] = tmp[2];
      }
    }
  });
  if (err) {
    return {err: err};
  }

  for (var tagName in requiredSigTags) {
    if (!tags.hasOwnProperty(tagName)) {
      return {err: "DKIM-Signature missing required tag "+ tagName};
    }
  }

  tags.h = tags.h.split(':');
  err = "DKIM-Signature h tag doesn't contain From";
  for (i = 0; i < tags.h.length; i++) {
    if (tags.h[i].match(/^from$/i)) {
      err = "";
      break;
    }
  }
  if (err) {
    return {err: err};
  }

  if (tags.i) {
    var itmp = tags.i.replace(/^.*?@/, '');
    err = "DKIM-Signature i tag not subdomain of d tag";
    while (itmp.match(/\./)) {
      if (itmp == tags.d) {
        err = "";
        break;
      } else {
        itmp = itmp.replace(/^.*?\./, '');
      }
    }
    if (err) {
      return {err: err};
    }
  }

  var expiry = parseInt(tags.x);
  if (tags.x && !isNaN(expiry) && isFinite(expiry)) {
    var now = Math.floor((new Date).getTime()/1000);
    if (now > expiry) {
      return {err: "DKIM-Signature expired"};
    }
  }

  if (tags.a != "rsa-sha1" && tags.a != "rsa-sha256") {
    return {err: "Invalid signing algorithm"};
  }

  // simple, simple/simple, simple/relaxed
  // relaxed, relaxed/relaxed, relaxed/simple
  if (!tags.c.match(/^(?:simple|relaxed)(?:\/(?:simple|relaxed))?$/)) {
    return {err: "Invalid canonicalization method"};
  }

  return {sigs:[tags]};
}

/**
 * <p>Verify body and header hashes</p>
 */
function verifyHashes(headers, body, sig, rec) {
  // figure out what kind of canonicalization needs to be done
  var hcanon = 'simple', bcanon = 'simple';
  if (sig.c) {
    var twoAlgos = sig.c.match(/^(simple|relaxed)\/(simple|relaxed)/);
    if (twoAlgos) {
      hcanon = twoAlgos[1];
      bcanon = twoAlgos[2];
    } else {
      hcanon = sig.c;
    }
  }

  // apply body canonicalization
  var bodyCanon, bodyHash;
  if (bcanon == 'relaxed') {
    bodyCanon = DKIMCanonicalizer.relaxedBody(body);
  } else {
    bodyCanon = DKIMCanonicalizer.simpleBody(body);
  }
  bodyHash = sha256(bodyCanon, 'base64');
  if (sig.bh != bodyHash) {
    return {err: "Body hash failed to verify"};
  }

  // verify signature on header hash
  // filter headers, append dkim-signature (w/o value of b=)
  // apply header canonicalization
  // calculate header hash, error if no match
}

/**
 * <p>Checks hash/key compatibililty between a signature and record.</p>
 *
 * @memberOf dkimsign
 * @param {Object} sig DKIM-Signature parsed with sigSanity
 * @param {Object} rec DKIM record parsed with recSanity
 *
 * @return {Object} The `err` key will be set if not compatible. Undefined is a match.
 */
function hashKeyMismatch(sig, rec) {
  var alg = sig.a.split('-', 2); // key, hash
  if (rec.h) {
    var err = "Mismatch between signature and record";
    var hashes = rec.h.split(/:/);
    for (var idx in hashes) {
      if (alg[1] == hashes[idx]) {
        err = "";
      }
    }
    if (err) {
      return {err: err+ ': unacceptable hash algorithm'};
    }
  }

  if (rec.k && rec.k != alg[0]) {
    return {err: 'Mismatch between signature and record: unacceptable key type'};
  }

  return undefined;
}

/**
 * <p>Verify a DKIM-signed message.</p>
 *
 * @memberOf dkimsign
 * @param {String} email Full e-mail source complete with headers.
 *
 * @return {Object} Object with `sigs` {Array} corresponding to any DKIM-Signature headers and `err` {String} if verification fails.
 */
function DKIMVerify(email) {
    var match = email.match(/^\r?\n|(?:\r?\n){2}/),
        headers = match && email.substr(0, match.index) || '',
        headerArray = splitHeaders(headers),
        body = match && email.substr(match.index + match[0].length) || email,
        rv = {sigs:[]}, sig, err, i;

    err = "No DKIM-Signature header";
    for (i = 0; i < headerArray.length; i++) {
      if (sig = headerArray[i].match(/^dkim\-signature:\s*(.*?)$/i)) {
        err = "";
        sig = sig[1].replace(/\s/, '');
        break; // FIXME: we only look at the first dkim-signature header for now
      }
    }
    if (err) {
      return {err: err};
    }

    var obj = sigSanity(sig);
    if (obj.err) {
      return {err: obj.err};
    }
    var sig = obj.sigs[0];

    // now we're talking to network services, so we return a promise
    return module.exports.KeyFromDNS(sig.s, sig.d)
      .then(function(txt) {
        console.log('KeyFromDNS success handler for '+ sig.s);
        obj = recSanity(txt);
        if (obj.err) {
          throw new Error(obj.err);
        }
        return obj.rec;

      }, function(error) {
        // handle KeyFromDNS failure
        // TODO: look for TXT record at doubled domain
        console.log('KeyFromDNS failure handler for '+ sig.s +': '+ error);
        throw new Error(error)

      })
      .then(function(rec) {
        err = hashKeyMismatch(sig, rec);
        if (err) {
          throw new Error(err.err);
        }
        return rec;

      })
      .then(function(rec) {
        err = verifyHashes(headers, body, sig, rec)
        if (err) {
          sig.result = false;
          sig.issue_desc = err;
        } else {
          sig.result = true;
        }
        rv.sigs.push(sig);
        return rv;

      })
      .fail(function(error) {
        console.log('chained failure handler for '+ tags.s +': '+ error);
      });
}

/**
 * <p>Split headers into an array.</p>
 *
 * @memberOf dkimsign
 * @param {String} headers E-mail headers part
 * @return {Array} Array of headers
 */
function splitHeaders(headers) {
  var headerLines = headers.split(/\r?\n|\r/), i;

  // join lines
  for (i = headerLines.length - 1; i >= 0; i--) {
      if (i && headerLines[i].match(/^\s/)) {
          headerLines[i - 1] += headerLines.splice(i, 1);
      }
  }

  return headerLines;
}

/**
 * <p>Get public key from specified domain's DNS.</p>
 *
 * @memberOf dkimsign
 * @param {String} selector Selector to use when looking up DKIM record
 * @param {String} domain Domain where DKIM record lives
 *
 * @return {Promise} Promise representing the results of the DNS TXT lookup.
 */
function KeyFromDNS(selector, domain) {
  var fqdn = selector +'._domainkey.'+ domain;
  return resolveTxt(fqdn)
    .then(function(res) {
      return res[0].join('');
    });
}

/**
 * <p>Generates a DKIM-Signature header field without the signature part ('b=' is empty)</p>
 *
 * @memberOf dkimsign
 * @private
 * @param {String} domainName Domain name to use for signing
 * @param {String} keySelector Selector for the DKMI public key
 * @param {String} headerFieldNames Header fields to sign
 * @param {String} headers E-mail headers
 * @param {String} body E-mail body
 *
 * @return {String} Mime folded DKIM-Signature string
 */
function generateDKIMHeader(domainName, keySelector, headerFieldNames, headers, body) {
    var canonicalizedBody = DKIMCanonicalizer.relaxedBody(body),
        canonicalizedBodyHash = sha256(canonicalizedBody, 'base64'),
        canonicalizedHeaderData = DKIMCanonicalizer.relaxedHeaders(headers, headerFieldNames),
        dkim;

    if (hasUTFChars(domainName)) {
        domainName = punycode.toASCII(domainName);
    }

    dkim = [
        'v=1',
        'a=rsa-sha256',
        'c=relaxed/relaxed',
        'd=' + domainName,
        'q=dns/txt',
        's=' + keySelector,
        'bh=' + canonicalizedBodyHash,
        'h=' + canonicalizedHeaderData.fieldNames
    ].join('; ');

    return libmime.foldLines('DKIM-Signature: ' + dkim, 76) + ';\r\n b=';
}

/**
 * <p>DKIM canonicalization functions</p>
 *
 * @memberOf dkimsign
 * @private
 */
var DKIMCanonicalizer = {

    /**
     * <p>Simple body canonicalization by rfc4871 #3.4.3</p>
     *
     * @param {String} body E-mail body part
     * @return {String} Canonicalized body
     */
    simpleBody: function(body) {
        return (body || '').toString().replace(/(?:\r?\n|\r)*$/, '\r\n');
    },

    /**
     * <p>Relaxed body canonicalization by rfc4871 #3.4.4</p>
     *
     * @param {String} body E-mail body part
     * @return {String} Canonicalized body
     */
    relaxedBody: function(body) {
        return (body || '').toString().
        replace(/\r?\n|\r/g, '\n').
        split('\n').
        map(function(line) {
            return line.replace(/\s*$/, ''). //rtrim
            replace(/\s+/g, ' '); // only single spaces
        }).
        join('\n').
        replace(/\n*$/, '\n').
        replace(/\n/g, '\r\n');
    },

    /**
     * <p>Relaxed headers canonicalization by rfc4871 #3.4.2 with filtering</p>
     *
     * @param {String} body E-mail headers part
     * @return {String} Canonicalized headers
     */
    relaxedHeaders: function(headers, fieldNames) {
        var includedFields = (fieldNames || '').toLowerCase().
        split(':').
        map(function(field) {
            return field.trim();
        }),
        headerFields = {},
        headerLines = headers.split(/\r?\n|\r/),
        line, i;

        // join lines
        for (i = headerLines.length - 1; i >= 0; i--) {
            if (i && headerLines[i].match(/^\s/)) {
                headerLines[i - 1] += headerLines.splice(i, 1);
            } else {
                line = DKIMCanonicalizer.relaxedHeaderLine(headerLines[i]);

                // on multiple values, include only the first one (the one in the bottom of the list)
                if (includedFields.indexOf(line.key) >= 0 && !(line.key in headerFields)) {
                    headerFields[line.key] = line.value;
                }
            }
        }

        headers = [];
        for (i = includedFields.length - 1; i >= 0; i--) {
            if (!headerFields[includedFields[i]]) {
                includedFields.splice(i, 1);
            } else {
                headers.unshift(includedFields[i] + ':' + headerFields[includedFields[i]]);
            }
        }

        return {
            headers: headers.join('\r\n') + '\r\n',
            fieldNames: includedFields.join(':')
        };
    },

    /**
     * <p>Relaxed header canonicalization for single header line</p>
     *
     * @param {String} line Single header line
     * @return {String} Canonicalized header line
     */
    relaxedHeaderLine: function(line) {
        var value = line.split(':'),
            key = (value.shift() || '').toLowerCase().trim();

        value = value.join(':').replace(/\s+/g, ' ').trim();

        return {
            key: key,
            value: value
        };
    }
};
module.exports.DKIMCanonicalizer = DKIMCanonicalizer;

/**
 * <p>Generates a SHA-256 hash</p>
 *
 * @param {String} str String to be hashed
 * @param {String} [encoding='hex'] Output encoding
 * @return {String} SHA-256 hash in the selected output encoding
 */
function sha256(str, encoding) {
    var shasum = crypto.createHash('sha256');
    shasum.update(str);
    return shasum.digest(encoding || 'hex');
}

/**
 * <p>Detects if a string includes unicode symbols</p>
 *
 * @param {String} str String to be checked
 * @return {String} true, if string contains non-ascii symbols
 */
function hasUTFChars(str) {
    var rforeign = /[^\u0000-\u007f]/;
    return !!rforeign.test(str);
}
