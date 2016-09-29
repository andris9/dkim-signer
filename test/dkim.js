var testCase = require('nodeunit').testCase,
    dkim = require("../lib/dkim"),
    fs = require("fs"),
    dns = require('dns'),
    publicKeys = {},
    realDNS = dkim.keyFromDNS;

function stubDNS(s, d, callback) {
  if (s === "dkim") {
    if (!publicKeys[s]) {
      var pem = publicKeys[s+".pem"] = fs.readFileSync(__dirname+"/keys/test_public.pem", "ascii");
      var key = publicKeys[s] = pem.split(/\r?\n|\r/)
        .filter(function(elt) {
          return !elt.match(/^\-\-\-/);
        }).join('');
      publicKeys[s+".txt"] = "v=DKIM1; k=rsa; h=sha256; p="+ key;
    }
  } else {

    var bitLen = 0,
        smatch = s.match(/^b(1024|2048)$/);
    if (!smatch) {
      callback(new Error("Unexpected selector format, use 'b1024' or 'b2048'"));
      return;
    }
    bitLen = smatch[1];
    if (!publicKeys[s]) {
      var pemFile = __dirname+"/keys/test_public_"+bitLen+".pem";
      var pem = publicKeys[s+".pem"] = fs.readFileSync(pemFile, "ascii");
      var key = publicKeys[s] = pem.split(/\r?\n|\r/)
        .filter(function(elt) {
          return !elt.match(/^\-\-\-/);
        }).join('');
      publicKeys[s+".txt"] = "v=DKIM1; k=rsa; p="+ key;
    }
  }
  callback(null, publicKeys[s+".txt"]);
}
dkim.keyFromDNS = stubDNS;

exports["Canonicalizer tests"] = {
    "Simple body undefined": function(test){
        var body = undefined;
        test.equal("\r\n", dkim.DKIMCanonicalizer.simpleBody(body));
        test.done();
    },
    "Simple body empty": function(test){
        var body = "";
        test.equal("\r\n", dkim.DKIMCanonicalizer.simpleBody(body));
        test.done();
    },
    "Simple body newlines": function(test){
        var body = "\n\n\n";
        test.equal("\r\n", dkim.DKIMCanonicalizer.simpleBody(body));
        test.done();
    },
    "Simple headers": function(test) {
      var headers = "A: X\r\nB: Y\r\n";
      var result = dkim.DKIMCanonicalizer.simpleHeaders(headers, "A:B").headers;
      test.equal("A: X\r\nB: Y\r\n", result);
      test.done();
    },
    "Simple headers multiline": function(test) {
      var headers = "A: X\r\nB: Z\r\n Z addendum\r\n";
      var result = dkim.DKIMCanonicalizer.simpleHeaders(headers, "A:B").headers;
      test.equal("A: X\r\nB: Z\r\n Z addendum\r\n", result);
      test.done();
    },
    "Simple headers dup header": function(test) {
      var headers = "A: X\r\nB: Y\r\nB: Z\r\n";
      var result = dkim.DKIMCanonicalizer.simpleHeaders(headers, "A:B").headers;
      test.equal("A: X\r\nB: Z\r\n", result);
      test.done();
    },
    "Relaxed body": function(test){
        // dkim.org samples
        var body = " C \r\nD \t E\r\n\r\n\r\n";
        test.equal(" C\r\nD E\r\n", dkim.DKIMCanonicalizer.relaxedBody(body));
        test.done();
    },
    "Relaxed body short": function(test){
        // dkim.org samples
        var body = " C \r\nD \t E";
        test.equal(" C\r\nD E\r\n", dkim.DKIMCanonicalizer.relaxedBody(body));
        test.done();
    },
    "Relaxed headers": function(test){
        var headers = "A: X\r\nB: Y\t\r\n\tZ  \r\n";
        test.equal("a:X\r\nb:Y Z\r\n", dkim.DKIMCanonicalizer.relaxedHeaders(headers, "a:b").headers);
        test.done();
    },
    "Relaxed headers dup header": function(test){
      var headers = "A: X\r\nB: Y\r\nB: Z\r\n";
      var result = dkim.DKIMCanonicalizer.relaxedHeaders(headers, "A:B").headers;
      test.equal("a:X\r\nb:Z\r\n", result);
      test.done();
    }
}

exports["Signing tests"] = {
    "Unicode domain": function(test){
        var mail = "From: andris@node.ee\r\nTo:andris@kreata.ee\r\n\r\nHello world!";
        var dkimField = dkim.DKIMSign(mail,{
            domainName: "müriaad-polüteism.info",
            keySelector: "dkim",
            privateKey: fs.readFileSync(__dirname+"/keys/test_private.pem")
        });
        test.equal(dkimField.replace(/\r?\n\s*/g, "").replace(/\s+/g, ""), "DKIM-Signature:v=1;a=rsa-sha256;c=relaxed/relaxed;d=xn--mriaad-polteism-zvbj.info;q=dns/txt;s=dkim;bh=z6TUz85EdYrACGMHYgZhJGvVy5oQI0dooVMKa2ZT7c4=;h=from:to;b=oBJ1MkwEkftfXa2AK4Expjp2xgIcAR43SVrftSEHVQ6F1SlGjP3EKP+cn/hLkhUel3rY0icthk/myDu6uhTBmM6DMtzIBW/7uQd6q9hfgaiYnw5Iew2tZc4TzBEYSdKi")
        test.done();
    },
    "Normal domain": function(test){
        var mail = "From: andris@node.ee\r\nTo:andris@kreata.ee\r\n\r\nHello world!";
        var dkimField = dkim.DKIMSign(mail,{
            domainName: "node.ee",
            keySelector: "dkim",
            privateKey: fs.readFileSync(__dirname+"/keys/test_private.pem")
        });
        test.equal(dkimField.replace(/\r?\n\s*/g, "").replace(/\s+/g, ""), "DKIM-Signature:v=1;a=rsa-sha256;c=relaxed/relaxed;d=node.ee;q=dns/txt;s=dkim;bh=z6TUz85EdYrACGMHYgZhJGvVy5oQI0dooVMKa2ZT7c4=;h=from:to;b=pVd+Dp+EjmYBcc1AWlBAP4ESpuAJ2WMS4gbxWLoeUZ1vZRodVN7K9UXvcCsLuqjJktCZMN2+8dyEUaYW2VIcxg4sVBCS1wqB/tqYZ/gxXLnG2/nZf4fyD2vxltJP4pDL");
        test.done();
    }
}

function testMsg() {
    var mail = "From: andris@node.ee\r\nTo:andris@kreata.ee\r\n\r\nHello world!";
    return mail;
}

function signMsg(testmsg, domain, selector, options) {
    var signOptions = {
        domainName: domain,
        keySelector: selector,
        privateKey: fs.readFileSync(__dirname+"/keys/test_private.pem")
    };
    for (var k in options) {
      signOptions[k] = options[k];
    }
    return dkim.DKIMSign(testmsg, signOptions);
}

function verifyTest(test, head_canon, body_canon, sign_alg, key_len) {
  var file = __dirname+"/msgs/"+[head_canon, body_canon, sign_alg, key_len].join('_')+".eml";
  var mail = fs.readFileSync(file, "ascii");
  // opendkim-testmsg stealth-fixes non-crlf line endings
  // we need to do the same, in order for simple canonicalization tests to pass
  // this is a testing-only issue, no impact on public-facing functionality
  mail = mail.replace(/\r?\n/g, '\r\n');
  dkim.DKIMVerify(mail, function(err, result) {
    test.equal(err, null);
    test.ok(result.result);
    if (!result.result) {
      console.log('ERROR: '+ result.issue_desc);
    }
    test.done();
  });
}

exports["OpenDKIM tests"] = {
  'Verify (relaxed, relaxed, rsa-sha256, 1024)': function(test){ verifyTest(test, 'relaxed', 'relaxed', 'rsa-sha256', '1024'); },
  'Verify (relaxed, relaxed, rsa-sha256, 2048)': function(test){ verifyTest(test, 'relaxed', 'relaxed', 'rsa-sha256', '2048'); },
  'Verify (relaxed, relaxed, rsa-sha1, 1024)': function(test){ verifyTest(test, 'relaxed', 'relaxed', 'rsa-sha1', '1024'); },
  'Verify (relaxed, relaxed, rsa-sha1, 2048)': function(test){ verifyTest(test, 'relaxed', 'relaxed', 'rsa-sha1', '2048'); },
  'Verify (relaxed, simple, rsa-sha256, 1024)': function(test){ verifyTest(test, 'relaxed', 'simple', 'rsa-sha256', '1024'); },
  'Verify (relaxed, simple, rsa-sha256, 2048)': function(test){ verifyTest(test, 'relaxed', 'simple', 'rsa-sha256', '2048'); },
  'Verify (relaxed, simple, rsa-sha1, 1024)': function(test){ verifyTest(test, 'relaxed', 'simple', 'rsa-sha1', '1024'); },
  'Verify (relaxed, simple, rsa-sha1, 2048)': function(test){ verifyTest(test, 'relaxed', 'simple', 'rsa-sha1', '2048'); },
  'Verify (simple, relaxed, rsa-sha256, 1024)': function(test){ verifyTest(test, 'simple', 'relaxed', 'rsa-sha256', '1024'); },
  'Verify (simple, relaxed, rsa-sha256, 2048)': function(test){ verifyTest(test, 'simple', 'relaxed', 'rsa-sha256', '2048'); },
  'Verify (simple, relaxed, rsa-sha1, 1024)': function(test){ verifyTest(test, 'simple', 'relaxed', 'rsa-sha1', '1024'); },
  'Verify (simple, relaxed, rsa-sha1, 2048)': function(test){ verifyTest(test, 'simple', 'relaxed', 'rsa-sha1', '2048'); },
  'Verify (simple, simple, rsa-sha256, 1024)': function(test){ verifyTest(test, 'simple', 'simple', 'rsa-sha256', '1024'); },
  'Verify (simple, simple, rsa-sha256, 2048)': function(test){ verifyTest(test, 'simple', 'simple', 'rsa-sha256', '2048'); },
  'Verify (simple, simple, rsa-sha1, 1024)': function(test){ verifyTest(test, 'simple', 'simple', 'rsa-sha1', '1024'); },
  'Verify (simple, simple, rsa-sha1, 2048)': function(test){ verifyTest(test, 'simple', 'simple', 'rsa-sha1', '2048'); }
}

exports["OpenDKIM double-signing tests"] = {
  'Verify (relaxed, relaxed, rsa-sha256, 1024_2048)': function(test){ verifyTest(test, 'relaxed', 'relaxed', 'rsa-sha256', '1024_2048'); }
}

/*
// TODO: verifying messages with more than two dkim signatures is not currently supported
//
// NB: what would need to happen for that to be supported is to add a new method 
// (for both canonicalization methods) to return the nth-from-last header, and then
// update (relaxed|simple)Headers to detect duplicate header names in the list and
// call the new method to get the newer dkim signatures instead of duplicating the 2nd one
exports["OpenDKIM triple-signing tests"] = {
  'Verify (relaxed, relaxed, rsa-sha256, 1024_2048_1024)': function(test){ verifyTest(test, 'relaxed', 'relaxed', 'rsa-sha256', '1024_2048_1024'); }
}
*

// uncomment this block and re-run to regenerate test cases to be pasted above
// since nodeunit doesn't seem to cope well with declaring tests in a loop
/*
var head_canons = ['relaxed', 'simple'],
    body_canons = ['relaxed', 'simple'],
    sign_algs = ['rsa-sha256', 'rsa-sha1'],
    key_lens = ['1024', '2048'];
for (var head_canon of head_canons) {
  for (var body_canon of body_canons) {
    for (var sign_alg of sign_algs) {
      for (var key_len of key_lens) {
        console.log("  'Verify ("+ [head_canon, body_canon, sign_alg, key_len].join(', ')
            +")': function(test){ verifyTest(test, '"+ [head_canon, body_canon, sign_alg, key_len].join("', '") +"'); },");
      }
    }
  }
}
*/

exports["Sign+verify tests"] = {
    "Unicode domain": function(test){
        var mail = testMsg();
        var dkimField = signMsg(mail, "müriaad-polüteism.info", "dkim");
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
          test.equal(err, null);
          test.ok(result.result);
          test.done();
        });
    },
    "Normal domain": function(test){
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee", "dkim");
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
          test.equal(err, null);
          test.ok(result.result);
          test.done();
        });
    },
    "Sig missing": function(test) {
        var mail = testMsg();
        dkim.DKIMVerify(mail, function(err, result) {
            test.equal(err, null);
            test.equal(result.result, false);
            test.equal(result.issue_desc, 'No DKIM-Signature header');
            test.done();
        });
    },
    "Sig malformed": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee", "dkim").toUpperCase();
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
            test.equal(err, null);
            test.equal(result.result, false);
            test.done();
        });
    },
    "Sig format: v=": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee", "dkim").replace('v=', 'Q=');
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
            test.equal(err, null);
            test.equal(result.result, false);
            test.equal(result.issue_desc, 'DKIM-Signature must start with v tag');
            test.done();
        });
    },
    "Sig format: missing tag": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee", "dkim").replace('h=', '');
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
            test.equal(err, null);
            test.equal(result.result, false);
            test.equal(result.issue_desc, 'DKIM-Signature missing required tag bh');
            test.done();
        });
    },
    // Section 3.2: Tags with duplicate names MUST NOT occur within a single tag-list; if
    // a tag name does occur more than once, the entire tag-list is invalid.
    "Sig format: dup tag": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee; d=node.ee", "dkim");
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
            test.equal(err, null);
            test.equal(result.result, false);
            test.equal(result.issue_desc, 'DKIM-Signature contains duplicate tag d');
            test.done();
        });
    },
    // Section 5.4: The From header field MUST be signed (that is, included in the "h="
    // tag of the resulting DKIM-Signature header field)
    "Sig format: h= missing From": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee", "dkim").replace('from:', '');
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
            test.equal(err, null);
            test.equal(result.result, false);
            test.equal(result.issue_desc, 'DKIM-Signature h tag doesn\'t contain From');
            test.done();
        });
    },

    "Sig format: i= not a subdomain of d=": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee; i=anode.ee", "dkim");
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
            test.equal(err, null);
            test.equal(result.result, false);
            test.equal(result.issue_desc, 'DKIM-Signature i tag not subdomain of d tag');
            test.done();
        });
    },
    "Sig expired": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee; x=1", "dkim");
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
            test.equal(err, null);
            test.equal(result.result, false);
            test.equal(result.issue_desc, 'DKIM-Signature expired');
            test.done();
        });
    },
    "Sig algo invalid": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee", "dkim").replace(/a=\S+/, 'a=rsa-md5;');
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
            test.equal(err, null);
            test.equal(result.result, false);
            test.equal(result.issue_desc, 'DKIM-Signature has invalid signing algorithm');
            test.done();
        });
    },
    "Canonicalization method invalid": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee", "dkim").replace(/c=\S+/, 'c=stressed/complex;');
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
            test.equal(err, null);
            test.equal(result.result, false);
            test.equal(result.issue_desc, 'DKIM-Signature has invalid canonicalization method');
            test.done();
        });
    },

    "Record missing": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee", "dkim");
        dkim.keyFromDNS = function(s, d, callback) {
            var err = new Error();
            err.code = dns.NOTFOUND;
            callback(err);
        };
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
            test.equal(err, null);
            test.equal(result.result, false);
            test.equal(result.issue_desc, 'DKIM public key not found');
            test.done();
        });
    },
    "Record malformed": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee", "dkim");
        dkim.keyFromDNS = function(s, d, callback) {
            stubDNS(s, d, function(err, result) {
                callback(null, result.toLowerCase());
            });
        };
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
            test.equal(err, null);
            test.equal(result.result, false);
            test.done();
        });
    },
    "Record format: dup tag": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee; d=node.ee", "dkim");
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
            test.equal(err, null);
            test.equal(result.result, false);
            test.done();
        });

    },
    "Record format: missing tag": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee", "dkim");
        dkim.keyFromDNS = function(s, d, callback) {
            stubDNS(s, d, function(err, result) {
                callback(null, result.replace(/p=[a-zA-Z0-9+/=]*/, ''));
            });
        };
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
            test.equal(err, null);
            test.equal(result.result, false);
            test.done();
        });
    },
    "Record format: v=DKIM1": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee", "dkim");
        dkim.keyFromDNS = function(s, d, callback) {
            stubDNS(s, d, function(err, result) {
                callback(null, result.replace(/v=[a-zA-Z0-9]+/, 'v=DEAD1'));
            });
        };
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
            test.equal(err, null);
            test.equal(result.result, false);
            test.ok(result.issue_desc.indexOf('Invalid DKIM record version') >= 0);
            test.done();
        });
    },
    "Record format: key invalid": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee", "dkim");
        dkim.keyFromDNS = function(s, d, callback) {
            stubDNS(s, d, function(err, result) {
                callback(null, result.replace(/k=[a-zA-Z0-9]+/, 'k=DSA'));
            });
        };
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
            test.equal(err, null);
            test.equal(result.result, false);
            test.ok(result.issue_desc.indexOf('invalid key type') >= 0);
            test.done();
        });
    },
    "Record revoked": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee", "dkim");
        dkim.keyFromDNS = function(s, d, callback) {
            stubDNS(s, d, function(err, result) {
                var r = result.replace(/p=[a-zA-Z0-9+/]+/, 'p=');
                callback(null, r);
            });
        };
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
            test.equal(err, null);
            test.equal(result.result, false);
            test.ok(result.issue_desc.indexOf('revoked') >= 0);
            test.done();
        });
    },
    "Message body verification fail": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee", "dkim");
        dkim.keyFromDNS = stubDNS;
        dkim.DKIMVerify(dkimField + "\r\n" + mail.toLowerCase(), function(err, result) {
            test.equal(err, null);
            if (test.equal(result.result, false, 'Body hash should not verify')) {
              test.ok(result.issue_desc.indexOf('Body hash failed to verify') >= 0);
            }
            test.done();
        });
    },
    "Message signature verification fail": function(test) {
        var mail = testMsg();
        var dkimField = signMsg(mail, "node.ee", "dkim");
        mail = mail.replace(/^(From:\s+andris@)(node.ee)$/im, '$1a$2');
        dkim.keyFromDNS = stubDNS;
        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
            test.equal(err, null);
            if (test.equal(result.result, false, 'Signature should not verify')) {
              test.ok(result.issue_desc.indexOf('Signature could not be verified') >= 0);
            }
            test.done();
        });
    }
}

exports["Sig content tests"] = {
  "Missing c tag": function(test) {
    var mail = testMsg();
    var dkimField = signMsg(mail, "node.ee", "dkim");
    // modify dkim sig to remove optional c= tag
    dkimField = dkimField.replace(/\s+c=(simple|relaxed)(\/(simple|relaxed))?;\s+/, ' ');
    dkim.keyFromDNS = stubDNS;
    dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
      test.equal(err, null);
      if (test.equal(result.result, false, 'Signature should not verify')) {
        test.ok(result.issue_desc.indexOf('Signature could not be verified') >= 0);
      }
      test.done();
    });
  }
}

// vim: ts=4:sw=4
