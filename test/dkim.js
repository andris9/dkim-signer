var testCase = require('nodeunit').testCase,
    dkim = require("../lib/dkim"),
    fs = require("fs"),
    publicKey = fs.readFileSync(__dirname+"/test_public.pem", 'ascii'),
    keyStr = publicKey.split(/\r?\n|\r/)
      .filter(function(elt) {
        return !elt.match(/^\-\-\-/);
      }).join(''),
    realDNS = dkim.keyFromDNS,
    stubDNS = function(s, d, callback) {
      callback(null, 'v=DKIM1; k=rsa; h=sha256; p='+keyStr);
    };

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
    }
}

exports["Signing tests"] = {
    "Unicode domain": function(test){
        var mail = "From: andris@node.ee\r\nTo:andris@kreata.ee\r\n\r\nHello world!";
        var dkimField = dkim.DKIMSign(mail,{
            domainName: "müriaad-polüteism.info",
            keySelector: "dkim",
            privateKey: fs.readFileSync(__dirname+"/test_private.pem")
        });
        test.equal(dkimField.replace(/\r?\n\s*/g, "").replace(/\s+/g, ""), "DKIM-Signature:v=1;a=rsa-sha256;c=relaxed/relaxed;d=xn--mriaad-polteism-zvbj.info;q=dns/txt;s=dkim;bh=z6TUz85EdYrACGMHYgZhJGvVy5oQI0dooVMKa2ZT7c4=;h=from:to;b=oBJ1MkwEkftfXa2AK4Expjp2xgIcAR43SVrftSEHVQ6F1SlGjP3EKP+cn/hLkhUel3rY0icthk/myDu6uhTBmM6DMtzIBW/7uQd6q9hfgaiYnw5Iew2tZc4TzBEYSdKi")
        test.done();
    },
    "Normal domain": function(test){
        var mail = "From: andris@node.ee\r\nTo:andris@kreata.ee\r\n\r\nHello world!";
        var dkimField = dkim.DKIMSign(mail,{
            domainName: "node.ee",
            keySelector: "dkim",
            privateKey: fs.readFileSync(__dirname+"/test_private.pem")
        });
        test.equal(dkimField.replace(/\r?\n\s*/g, "").replace(/\s+/g, ""), "DKIM-Signature:v=1;a=rsa-sha256;c=relaxed/relaxed;d=node.ee;q=dns/txt;s=dkim;bh=z6TUz85EdYrACGMHYgZhJGvVy5oQI0dooVMKa2ZT7c4=;h=from:to;b=pVd+Dp+EjmYBcc1AWlBAP4ESpuAJ2WMS4gbxWLoeUZ1vZRodVN7K9UXvcCsLuqjJktCZMN2+8dyEUaYW2VIcxg4sVBCS1wqB/tqYZ/gxXLnG2/nZf4fyD2vxltJP4pDL");
        test.done();
    }
}

exports["Sign+verify tests"] = {
    "Unicode domain": function(test){
        var mail = "From: andris@node.ee\r\nTo:andris@kreata.ee\r\n\r\nHello world!";
        var dkimField = dkim.DKIMSign(mail,{
            domainName: "müriaad-polüteism.info",
            keySelector: "dkim",
            privateKey: fs.readFileSync(__dirname+"/test_private.pem")
        });
        test.equal(dkimField.replace(/\r?\n\s*/g, "").replace(/\s+/g, ""), "DKIM-Signature:v=1;a=rsa-sha256;c=relaxed/relaxed;d=xn--mriaad-polteism-zvbj.info;q=dns/txt;s=dkim;bh=z6TUz85EdYrACGMHYgZhJGvVy5oQI0dooVMKa2ZT7c4=;h=from:to;b=oBJ1MkwEkftfXa2AK4Expjp2xgIcAR43SVrftSEHVQ6F1SlGjP3EKP+cn/hLkhUel3rY0icthk/myDu6uhTBmM6DMtzIBW/7uQd6q9hfgaiYnw5Iew2tZc4TzBEYSdKi")
        test.done();
    },
    "Normal domain": function(test){
        var mail = "From: andris@node.ee\r\nTo:andris@kreata.ee\r\n\r\nHello world!";
        var dkimField = dkim.DKIMSign(mail, {
            domainName: "node.ee",
            keySelector: "dkim",
            privateKey: fs.readFileSync(__dirname+"/test_private.pem")
        });

        dkim.keyFromDNS = stubDNS;

        dkim.DKIMVerify(dkimField + "\r\n" + mail, function(err, result) {
          test.equal(err, null);
          test.ok(result.result);
          test.done();
        });
    },
    "Sig missing": function(test) {test.done();},
    "Sig malformed": function(test) {test.done();},
    "Sig format: v=": function(test) {test.done();},
    "Sig format: missing tag": function(test) {test.done();},
    "Sig format: dup tag": function(test) {test.done();},
    "Sig format: h= missing From": function(test) {test.done();},
    "Sig format: i= not a subdomain of d=": function(test) {test.done();},
    "Sig expired": function(test) {test.done();},
    "Sig algo invalid": function(test) {test.done();},
    "Canonicalization method invalid": function(test) {test.done();},
    "Record missing": function(test) {test.done();},
    "Record incorrect location": function(test) {test.done();},
    "Record malformed": function(test) {test.done();},
    "Record format: dup tag": function(test) {test.done();},
    "Record format: missing tag": function(test) {test.done();},
    "Record format: v=": function(test) {test.done();},
    "Record format: DKIM1": function(test) {test.done();},
    "Record format: key invalid": function(test) {test.done();},
    "Record hash algo invalid": function(test) {test.done();},
    "Record revoked": function(test) {test.done();},
    "Record service type invalid": function(test) {test.done();},
    "Record / sig mismatch": function(test) {test.done();},
    "Message body verification fail": function(test) {test.done();},
    "Message signature verification fail": function(test) {test.done();}
}

