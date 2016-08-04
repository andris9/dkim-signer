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

var SignatureTags = {
  name: "DKIM-Signature",
  required: {
    v: true, a: true, b: true, bh: true, d: true, s: true, h: true
  }, optional: {
    c: true, i: true, l: true, q: true, t: true, x: true, z: true
  }
};

var RecordTags = {
  name: "DKIM record",
  required: { p: true },
  optional: {
    v: true, g: true, h: true, k: true, n: true, s: true, t: true
  }
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
 * <p>Split a semicolon-separated k=v list out into an object. Enforces required fields, if specified.</p>
 *
 * @memberOf dkimsign
 * @param {String} listStr Semicolon-separated k=v list
 * @param {Object} tagSpec Object specifying required/optional fields
 *
 * @return {Object} Object mapping {k: v} for all valid tags
 */
function tagObject(listStr, tagSpec) {
  var tags = {}, tmp, tagName;
  listStr.split(/\s*;\s*/).map(function(kv) {
    tmp = kv.replace(/\s+/, '').match(/^(\w+)\s*?=\s*?(.*)$/);
    if (tmp) {
      if (tags.hasOwnProperty(tmp[1]) && (tagSpec.required[tmp[1]] || tagSpec.optional[tmp[1]]) ) {
        throw new Error(tagSpec.name +" contains duplicate tag "+ tmp[1]);
      } else {
        tags[tmp[1]] = tmp[2];
      }
    }
  });
  for (tagName in tagSpec.required) {
    if (!tags.hasOwnProperty(tagName)) {
      throw new Error(tagSpec.name +" missing required tag "+ tagName);
    }
  }
  return tags;
}

/**
 * <p>Perform sanity checks on a DKIM record, fetched from DNS.</p>
 *
 * @memberOf dkimsign
 * @param {String} rec DKIM record
 *
 * @return {Object} Object with tag/value from record
 */
function recSanity(rec) {
  var err, i;
  /* Naive format validation (more thorough validation later):
   * DKIM records have one required tag,
   * and an equals sign must come after the tag.
   */
  if (!rec.match(/=/)) {
    throw new Error("Invalid DKIM record format");
  }

  var tags = tagObject(rec, RecordTags);

  if (tags.v) {
    if (!rec.match(/^v\s*=\s*/)) {
      throw new Error("Optional v tag must be first if present in DKIM record");
    } else if (tags.v != "DKIM1") {
      throw new Error("Invalid DKIM record version, use DKIM1");
    }
  }

  // TODO: support for g tag, interacts with i tag

  if (tags.h) {
    if (tags.h != "sha1" && tags.h != "sha256") {
      throw new Error("DKIM record has invalid hashing algorithm");
    }
  }

  if (tags.k) {
    if (tags.k != "rsa") {
      throw new Error("DKIM record has invalid key type");
    }
  }

  if (tags.p === "") {
    throw new Error("DKIM record has been revoked");
  }

  if (tags.s) {
    if (tags.s != "*" && tags.s != "email") {
      throw new Error("DKIM record has invalid service type");
    }
  }

  // TODO: support for t tag; colon-separated list of flags

  return tags;
}

/**
 * <p>Perform sanity checks on a DKIM signature, sent with a message.</p>
 *
 * @memberOf dkimsign
 * @param {String} sig DKIM-Signature header value
 *
 * @return {Object} Object with tag/value from signature
 */
function sigSanity(sig) {
  var err, i;
  if (!sig.match(/;/)) {
    throw new Error("Invalid DKIM-Signature format");
  }

  if (!sig.match(/^v\s*=\s*/)) {
    throw new Error("DKIM-Signature must start with v tag");
  }

  var tags = tagObject(sig, SignatureTags);

  tags.h = tags.h.split(':');
  err = "DKIM-Signature h tag doesn't contain From";
  for (i = 0; i < tags.h.length; i++) {
    if (tags.h[i].match(/^from$/i)) {
      err = "";
      break;
    }
  }
  if (err) {
    throw new Error(err);
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
      throw new Error(err);
    }
  }

  var expiry = parseInt(tags.x);
  if (tags.x && !isNaN(expiry) && isFinite(expiry)) {
    var now = Math.floor((new Date()).getTime()/1000);
    if (now > expiry) {
      throw new Error("DKIM-Signature expired");
    }
  }

  if (tags.a != "rsa-sha1" && tags.a != "rsa-sha256") {
    throw new Error("Invalid signing algorithm");
  }

  // simple, simple/simple, simple/relaxed
  // relaxed, relaxed/relaxed, relaxed/simple
  if (!tags.c.match(/^(?:simple|relaxed)(?:\/(?:simple|relaxed))?$/)) {
    throw new Error("Invalid canonicalization method");
  }

  return tags;
}

/**
 * <p>Verify body and header hashes</p>
 *
 * @memberOf dkimsign
 * @param headers {String} The header portion of the message
 * @param body {String} The body portion of the message
 * @param sig {Object} Parsed DKIM-Signature header from message headers
 * @param rec {Object} Parsed DKIM record from DNS
 *
 * @return {Object} Undefined means valid. Throws an Error if invalid.
 */
function AssertValidHashes(headers, body, sig, rec) {
  // figure out what kind of canonicalization needs to be done
  var hcanon = 'simple',
      bcanon = 'simple',
      bodyCanon, bodyHash, headCanon, headSig, verifier;

  // when signature specifies canonicalization, override the defaults
  if (sig.c) {
    var twoCanons = sig.c.match(/^(simple|relaxed)\/(simple|relaxed)/);
    if (twoCanons) {
      hcanon = twoCanons[1];
      bcanon = twoCanons[2];
    } else {
      /* https://tools.ietf.org/html/rfc4871#section-3.5
       * If only one algorithm is named, that algorithm is used for the
       * header and "simple" is used for the body.  For example,
       * "c=relaxed" is treated the same as "c=relaxed/simple".
       */
      hcanon = sig.c;
    }
  }

  // apply body canonicalization
  if (bcanon == 'relaxed') {
    bodyCanon = DKIMCanonicalizer.relaxedBody(body);
  } else {
    bodyCanon = DKIMCanonicalizer.simpleBody(body);
  }
  bodyHash = sha256(bodyCanon, 'base64');
  if (sig.bh != bodyHash) {
    throw new Error("Body hash failed to verify");
  }

  // verify signature on header hash
  verifier = crypto.createVerify(sig.a.toUpperCase());
  if (hcanon == 'relaxed') {
    // filter headers, append dkim-signature (w/o value of b=)
    headCanon = DKIMCanonicalizer.relaxedHeaders(headers, sig.h.join(':'));
    // TODO: headerGet and headerSplice helper functions
    var dkimMatch = headers.match(/^dkim\-signature:.*?\r?\n(?:\s+\S.*?\r?\n)*/im),
        dkimNoSig = dkimMatch[0].replace(/\bb=([^;]+)/, 'b='),
        dkimHead = DKIMCanonicalizer.relaxedHeaderLine(dkimNoSig);
    headCanon.headers += dkimHead.key +':'+ dkimHead.value;
    verifier.update(headCanon.headers);
  } else {
    throw new Error('Simple header canonicalization is not implemented');
    //headCanon = DKIMCanonicalizer.simpleHeaders();
  }

  var pubKeyPEM =
    '-----BEGIN PUBLIC KEY-----\n'+
    rec.p.replace(/(.{1,64})/g, '$1\n')+
    '-----END PUBLIC KEY-----\n';
  if (!verifier.verify(pubKeyPEM, sig.b, 'base64')) {
    throw new Error("Signature could not be verified");
  }
  return undefined;
}

/**
 * <p>Checks hash/key compatibililty between a signature and record.</p>
 *
 * @memberOf dkimsign
 * @param {Object} sig DKIM-Signature parsed with sigSanity
 * @param {Object} rec DKIM record parsed with recSanity
 *
 * @return {Object} Undefined is a match. Throws an Error on mismatch.
 */
function AssertHashKeyMatch(sig, rec) {
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
      throw new Error(err+ ': unacceptable hash algorithm');
    }
  }

  if (rec.k && rec.k != alg[0]) {
    throw new Error('Mismatch between signature and record: unacceptable key type');
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
        sig, err, i;

    err = "No DKIM-Signature header";
    for (i = 0; i < headerArray.length; i++) {
      sig = headerArray[i].match(/^dkim\-signature:\s*(.*?)$/i);
      if (sig) {
        err = "";
        sig = sig[1].replace(/\s/, '');
        break; // FIXME: we only look at the first dkim-signature header for now
      }
    }
    if (err) {
      throw new Error(err);
    }

    sig = sigSanity(sig);

    // now we're potentially talking to network services, so we return a promise
    return module.exports.KeyFromDNS(sig.s, sig.d)
      .then(recSanity, function(error) {
        // handle KeyFromDNS failure
        // TODO: look for TXT record at doubled domain:
        // foo._domainkey.example.com.example.com
        // and throw a custom error for that case
        console.log('KeyFromDNS failure handler for '+ sig.s +': '+ error);
        throw new Error(error);

      })
      .then(function(rec) {
        AssertHashKeyMatch(sig, rec);
        return rec;

      })
      .then(function(rec) {
        sig.result = true;
        try {
          AssertValidHashes(headers, body, sig, rec);
        } catch (err) {
          sig.result = false;
          sig.issue_desc = err;
        }
        return sig;
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
  // FIXME: make this (optionally?) non-destructive
  // so it can be used for simple header canonicalization
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
 * @return {Promise} Promise for results of the DNS TXT lookup.
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
