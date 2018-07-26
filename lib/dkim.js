'use strict';

var crypto = require('crypto');
var libmime = require('libmime');
var punycode = require('punycode');
var dns = require('dns');

/**
 * @namespace DKIM Signer module
 * @name dkimsign
 */
module.exports.DKIMSign = DKIMSign;
module.exports.DKIMVerify = DKIMVerify;
module.exports.generateDKIMHeader = generateDKIMHeader;
module.exports.sha256 = sha256;
module.exports.sha1 = sha1;
module.exports.keyFromDNS = keyFromDNS;
module.exports.hashAlgos = {
  sha1: sha1,
  sha256: sha256
};

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
 * <p>Split a raw email message into headers and body.</p>
 *
 * @memberOf dkimsign
 * @param {String} email Full email source complete with headers and body
 *
 * @return {Object} Object with `headers` and `body` keys
 */
function splitMessage(email) {
  // split email into headers and body
  // empty header section when email begins with CR?LF
  // or when email doesn't contain 2*CR?LF
  var match = email.match(/^\r?\n|((?:\r?\n)){2}/),
      headers = match && email.substr(0, match.index) || '',
      body = match && email.substr(match.index + match[0].length) || email;
  if (match && match[1]) {
    // make sure last header before body includes trailing newline
    headers = headers + match[1];
  }
  return {headers: headers, body: body};
}

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
 * @param {String} options.hashAlgo Hash algorithm for use in signature generation
 *
 * @return {String} Signed DKIM-Signature header field for prepending
 */
function DKIMSign(email, options) {
    options = options || {};
    email = (email || '').toString('utf-8');

    var hashAlgo = options.hashAlgo || 'SHA256';
    hashAlgo = hashAlgo.trim().toUpperCase();

    // split email into headers and body
    // empty header section when email begins with CR?LF
    // or when email doesn't contain 2*CR?LF
    var eml = splitMessage(email),
        headers = eml.headers,
        body = eml.body;

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

    signer = crypto.createSign('RSA-' + hashAlgo);
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
  for (var kv of listStr.split(/\s*;\s*/)) {
    tmp = kv.replace(/\s+/, '').match(/^(\w+)\s*?=\s*?(.*)$/);
    if (tmp) {
      if (tags.hasOwnProperty(tmp[1]) && (tagSpec.required[tmp[1]] || tagSpec.optional[tmp[1]]) ) {
        return {ok: false, msg: tagSpec.name +" contains duplicate tag "+ tmp[1]};
      } else {
        tags[tmp[1]] = tmp[2];
      }
    }
  }
  for (tagName in tagSpec.required) {
    if (!tags.hasOwnProperty(tagName)) {
      return {ok: false, msg: tagSpec.name +" missing required tag "+ tagName};
    }
  }
  return {ok: true, tags: tags};
}

/**
 * <p>Parse and sanity check a DKIM record fetched from DNS.</p>
 *
 * @memberOf dkimsign
 * @param {String} rec DKIM record
 *
 * @return {Object} Object with tag/value from record
 */
function parseDKIMRecord(rec) {
  var err, i;
  /* Naive format validation (more thorough validation later):
   * DKIM records have one required tag,
   * and an equals sign must come after the tag.
   */
  if (!rec.match(/=/)) {
    return {ok: false, msg: "Invalid DKIM record format"};
  }

  var tags = tagObject(rec, RecordTags);
  if (!tags.ok) {
    return {ok: false, msg: tags.msg};
  }
  tags = tags.tags;

  if (tags.v) {
    if (!rec.match(/^v\s*=\s*/)) {
      return {ok: false, msg: "Optional v tag must be first if present in DKIM record"};
    } else if (tags.v != "DKIM1") {
      return {ok: false, msg: "Invalid DKIM record version, use DKIM1"};
    }
  }

  // TODO: support for g tag, interacts with i tag

  if (tags.h) {
    if (tags.h != "sha1" && tags.h != "sha256") {
      return {ok: false, msg: "DKIM record has invalid hashing algorithm"};
    }
  }

  if (tags.k) {
    if (tags.k != "rsa") {
      return {ok: false, msg: "DKIM record has invalid key type"};
    }
  }

  if (tags.p === "") {
    return {ok: false, msg: "DKIM record has been revoked"};
  }

  if (tags.s) {
    if (tags.s != "*" && tags.s != "email") {
      return {ok: false, msg: "DKIM record has invalid service type"};
    }
  }

  // TODO: support for t tag; colon-separated list of flags

  return {ok: true, tags: tags};
}

/**
 * <p>Extract, parse and sanity check a DKIM signature from a set of canonicalised headers.</p>
 *
 * @memberOf dkimsign
 * @param {String} sig DKIM-Signature header value
 *
 * @return {Object} Object with tag/value from signature
 */
function parseSignatureFromHeader(sig) {
  var err, i;

  sig = sig.replace(/^dkim\-signature:\s*/i, '')
          .replace(/\s+/g, '')
          .replace(/;/g, '; ');

  if (!sig.match(/;/)) {
    return {ok: false, msg: "Invalid DKIM-Signature format"};
  }

  if (!sig.match(/^v\s*=\s*/)) {
    return {ok: false, msg: "DKIM-Signature must start with v tag"};
  }

  var tags = tagObject(sig, SignatureTags);
  if (!tags.ok) {
    return {ok: false, msg: tags.msg};
  }
  tags = tags.tags;

  tags.h = tags.h.split(':');
  err = "DKIM-Signature h tag doesn't contain From";
  for (i = 0; i < tags.h.length; i++) {
    if (tags.h[i].match(/^from$/i)) {
      err = "";
      break;
    }
  }
  if (err) {
    return {ok: false, msg: err};
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
      return {ok: false, msg: err};
    }
  }

  var expiry = parseInt(tags.x);
  if (tags.x && !isNaN(expiry) && isFinite(expiry)) {
    var now = Math.floor((new Date()).getTime()/1000);
    if (now > expiry) {
      return {ok: false, msg: "DKIM-Signature expired"};
    }
  }

  if (tags.a != "rsa-sha1" && tags.a != "rsa-sha256") {
    return {ok: false, msg: "DKIM-Signature has invalid signing algorithm"};
  }

  // simple, simple/simple, simple/relaxed
  // relaxed, relaxed/relaxed, relaxed/simple
  if (tags.c && !tags.c.match(/^(?:simple|relaxed)(?:\/(?:simple|relaxed))?$/)) {
    return {ok: false, msg: "DKIM-Signature has invalid canonicalization method"};
  }

  return {ok: true, tags: tags};
}

/**
 * <p>Verify DKIM signature on a prepared message.</p>
 *
 * @memberOf dkimsign
 * @param headers {String} The header portion of the message
 * @param body {String} The body portion of the message
 * @param sig {Object} Parsed DKIM-Signature header from message headers
 * @param rec {Object} Parsed DKIM record from DNS
 *
 * @return {Object} Undefined means valid. Throws an Error if invalid.
 */
function verifyMessageSignature(headers, body, sig, rec) {
  // figure out what kind of canonicalization needs to be done
  var hcanon = 'simple',
      bcanon = 'simple',
      bodyCanon, bodyHash, headCanon, headSig, verifier,
      sigHashAlgo = rec.h ? rec.h : sig.a.split('-')[1];

  sigHashAlgo = sigHashAlgo.toLowerCase();

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

  // verify body hash
  if (!(sigHashAlgo in module.exports.hashAlgos)) {
    return {ok: false, msg: 'Invalid hashing algorithm'};
  }
  bodyHash = module.exports.hashAlgos[sigHashAlgo](bodyCanon, 'base64');
  if (sig.bh != bodyHash) {
    return {ok: false, msg: "Body hash failed to verify"};
  }

  // filter headers, append dkim-signature (w/o value of b=)
  var dkimNoSig = sig.header.replace(/\bb=[^;]+/, 'b='),
      dkimHead;
  if (hcanon == 'relaxed') {
    //console.log('\nGETTING headers from:\n'+ headers);
    headCanon = DKIMCanonicalizer.relaxedHeaders(headers, sig.h.join(':'));
    dkimHead = DKIMCanonicalizer.relaxedHeaderLine(dkimNoSig);
    headCanon.headers += dkimHead.key +':'+ dkimHead.value;
  } else {
    // hcanon == 'simple'
    headCanon = DKIMCanonicalizer.simpleHeaders(headers, sig.h.join(':'));
    headCanon.headers += dkimNoSig;
  }

  //console.log('\nVERIFYING ['+ hcanon +'] header signature for:\n'+ headCanon.headers +'\n');

  // verify signature on header hash
  verifier = crypto.createVerify(sig.a.toUpperCase());
  verifier.update(headCanon.headers);

  var pubKeyPEM =
    '-----BEGIN PUBLIC KEY-----\n'+
    rec.p.replace(/(.{1,64})/g, '$1\n')+
    '-----END PUBLIC KEY-----\n';

  var verified = false;
  try {
    verified = verifier.verify(pubKeyPEM, sig.b, 'base64');
  } catch(e) {
    // dont.evenworryabout.it
  }

  if (!verified) {
    return {ok: false, msg: "Signature could not be verified"};
  }
  return {ok: true};
}

/**
 * <p>Checks hash/key compatibility between a signature and record.</p>
 *
 * @memberOf dkimsign
 * @param {Object} sig DKIM-Signature parsed with parseSignatureFromHeader
 * @param {Object} rec DKIM record parsed with parseDKIMRecord
 *
 * @return {Object} Undefined is a match. Throws an Error on mismatch.
 */
function checkHashCompatibility(sig, rec) {
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
      return {ok: false, msg: err+ ': unacceptable hash algorithm'};
    }
  }

  if (rec.k && rec.k != alg[0]) {
    return {ok: false, msg: 'Mismatch between signature and record: unacceptable key type'};
  }

  return {ok: true};
}

/**
 * <p>Verify a DKIM-signed message.</p>
 *
 * @memberOf dkimsign
 * @param {String} email Full e-mail source complete with headers.
 *
 * @return {Object} Object with 1+ DKIM-Signature header validation results. 
 */
function DKIMVerify(email, callback, sigs) {
    var eml = splitMessage(email),
        headers = eml.headers,
        body = eml.body,
        sigHeader = DKIMCanonicalizer.relaxedHeaders(headers, 'dkim-signature'),
        sig,
        rec,
        checkHashResult,
        verifyResult,
        i;

    // this is how relaxedHeaders indicates "no headers found"
    if (!sigHeader.fieldNames) {
      // not reached on recursive calls, so we don't return sigs
      return callback(null, {result: false, issue_desc: "No DKIM-Signature header"});
    }

    // context used internally when recursing to handle 2+ signatures
    sigs = sigs || {sigs:[]};
    sig = parseSignatureFromHeader(sigHeader.headers);
    if (!sig.ok) {
      // (potentially recursive) verification failure: parse error
      // add the header that failed parsing to sigs
      // set top-level error detail
      sigs.result = false;
      sigs.issue_desc = sig.msg;
      sigs.sigs.push({h:sigHeader.headers, result: false});
      return callback(null, sigs);
    }

    sig = sig.tags;
    if (sig.c && sig.c.match(/^simple/)) {
      sigHeader = DKIMCanonicalizer.simpleHeaders(headers, 'dkim-signature');
    }
    sig.warnings = [];
    checkMissingSigningHeaders(sig);

    // save the header we successfully parsed
    sig.header = sigHeader.headers;
    // push object with header and tags into our return value
    sigs.sigs.push(sig);

    module.exports.keyFromDNS(sig.s, sig.d, function(err, rawRec) {
      if (err) {
        // TODO: look for TXT record at doubled domain:
        // foo._domainkey.example.com.example.com
        // and return a custom error for that case
        if (err.code === dns.NOTFOUND) {
          sigs.result = sig.result = false;
          sigs.issue_desc = sig.issue_desc = 'DKIM public key not found';
          return callback(null, sigs);
        }

        // The other DNS errors are operational in nature;
        sigs.result = sig.result = false;
        sigs.issue_desc = sig.issue_desc = 'There was an error while fetching the DNS record';
        sigs.issue_desc_detail = sig.issue_desc_detail = [sig.s, sig.d, err.code, err.message].join(' | ');

        return callback(null, sigs); // just return the sigs or else we will breaks promisification
      }

      if (!rawRec) {
        return callback(new Error('DNS lookup for ' + sig.d + ' returned an empty result'));
      }

      rec = parseDKIMRecord(rawRec);
      if (!rec.ok) {
        sigs.result = sig.result = false;
        sigs.issue_desc = sig.issue_desc = rec.msg;
        return callback(null, sigs);
      }
      rec = rec.tags;

      checkHashResult = checkHashCompatibility(sig, rec);
      if (!checkHashResult.ok) {
        sigs.result = sig.result = false;
        sigs.issue_desc = sig.issue_desc = checkHashResult.msg;
        return callback(null, sigs);
      }

      if (sigs.sigs.length > 1) {
        // we're processing signature 2+; add back the most recent signature
        var sigHdrs = [];
        for (var idx = sigs.sigs.length - 2; idx >= 0; idx--) {
          sigHdrs.push(sigs.sigs[idx].header);
        }
        headers = headers + sigHdrs.join('');
        //console.log('APPENDING previous sigs:\n'+ sigHdrs);
      }
      verifyResult = verifyMessageSignature(headers, body, sig, rec);
      sigs.result = sig.result = verifyResult.ok;
      if (!verifyResult.ok) {
        //console.log('\nVERIFY failed: '+ verifyResult.msg);
        sigs.issue_desc = sig.issue_desc = verifyResult.msg;
        return callback(null, sigs);
      }

      var more = moreSignatures(email);
      if (more) {
        //console.log('\nRECURSING next signature, headers:\n'+ more.headers);
        return DKIMVerify(more.headers +'\r\n'+ more.body, callback, sigs);
      } else {
        return callback(null, sigs);
      }
    });
}

function checkMissingSigningHeaders(sig) {
  var headersToWarnOnMissing = ['date', 'subject'],
    lowerCaseHeaders = [],
    i;

  //convert all headers to lowercase
  for(i = 0; i < sig.h.length; i++){
    lowerCaseHeaders.push(sig.h[i].toLowerCase());
  }

  for (i = 0; i < headersToWarnOnMissing.length; i++) {
    if (lowerCaseHeaders.indexOf(headersToWarnOnMissing[i]) === -1) {
      sig.warnings.push('Signing the ' + headersToWarnOnMissing[i] + ' header is strongly recommended!');
    }
  }

}

/**
 * <p>Remove "oldest" header, checks for more sigs.</p>
 */
function moreSignatures(email) {
  var eml = splitMessage(email) 
    , oldest = DKIMCanonicalizer.simpleHeaders(eml.headers, 'dkim-signature')
    , sigPos, next;

  if (!oldest.fieldNames) {
    // no dkim-signature to remove
    return false;
  }

  sigPos = eml.headers.indexOf(oldest.headers);
  // slice the oldest sig out of the header block
  eml.headers = eml.headers.substring(0, sigPos)
    + eml.headers.substring(sigPos + oldest.headers.length);

  next = DKIMCanonicalizer.simpleHeaders(eml.headers, 'dkim-signature');
  if (!next.fieldNames) {
    // we just removed the last dkim-signature
    return false;
  }

  return eml;
}

/**
 * <p>Get public key from specified domain's DNS.</p>
 *
 * @memberOf dkimsign
 * @param {String} selector Selector to use when looking up DKIM record
 * @param {String} domain Domain where DKIM record lives
 */
function keyFromDNS(selector, domain, callback) {
  var fqdn = selector +'._domainkey.'+ domain;

  dns.resolveTxt(fqdn, function(err, res) {
    if (err) {
      callback(err);
      return;
    }
    callback(null, res ? res[0].join('') : null);
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
     * <p>Simple headers canonicalization by rfc4871 #3.4.1 with filtering</p>
     *
     * @param {String} body E-mail headers part
     * @return {String} Canonicalized headers
     */
    simpleHeaders: function(headers, fieldNames) {
        var includedHeaderNames = (fieldNames || '').split(':').
        map(function(field) {
          return field.trim().toLowerCase();
        }),
        headerLines = headers.split(/(\r?\n|\r)/),
        headers = [],
        headerIndex = {},
        foundHeaders = '',
        foundHeaderNames = [],
        i;

        // Coalesce newlines, multiline headers
        for (i = headerLines.length - 1; i >= 0; --i) {
          var chunk = headerLines[i],
              lastChunk = headerLines[i - 1];
          if (chunk.length == 0) {
            continue;
          }
          // this chunk is a newline, or begins with whitespace, so combine it
          if (chunk.match(/^(?:\r?\n|\r)$/) || chunk.match(/^\s+/)) {
            headerLines[i - 1] = lastChunk + chunk;
          } else {
            headers.unshift(chunk);
          }
        }

        // Form a header name -> line number index
        headers.forEach(function(hdr, idx) {
          var hdrName = hdr.split(':').shift() || '';
          hdrName = hdrName.toLowerCase();
          if (hdrName in headerIndex) {
            headerIndex[hdrName].push(idx);
          } else {
            headerIndex[hdrName] = [idx];
          }
        });

        // Form canonicalized header block
        includedHeaderNames.forEach(function(hdrName) {
          if (hdrName in headerIndex) {
            var lines = headerIndex[hdrName];
            foundHeaders += headers[lines.pop()];
            foundHeaderNames.push(hdrName);
          }
        });

        return {
            headers: foundHeaders,
            fieldNames: foundHeaderNames.join(':')
        };
    },

    /**
     * <p>Relaxed headers canonicalization by rfc4871 #3.4.2 with filtering</p>
     *
     * @param {String} body E-mail headers part
     * @return {String} Canonicalized headers
     */
    relaxedHeaders: function(headers, fieldNames) {
        var signedHeaders = (fieldNames || '').toLowerCase().
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
                if (signedHeaders.indexOf(line.key) >= 0 && !(line.key in headerFields)) {
                    headerFields[line.key] = line.value;
                }
            }
        }

        headers = [];
        for (i = signedHeaders.length - 1; i >= 0; i--) {
            if (headerFields[signedHeaders[i]] === undefined) {
                signedHeaders.splice(i, 1);
            } else {
                headers.unshift(signedHeaders[i] + ':' + headerFields[signedHeaders[i]]);
            }
        }

        return {
            headers: headers.join('\r\n') + '\r\n',
            fieldNames: signedHeaders.join(':')
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
 * <p>Generates a SHA-1 hash</p>
 *
 * @param {String} str String to be hashed
 * @param {String} [encoding='hex'] Output encoding
 * @return {String} SHA-1 hash in the selected output encoding
 */
function sha1(str, encoding) {
    var shasum = crypto.createHash('sha1');
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
