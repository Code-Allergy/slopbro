/* SlopBro security fork. AGPL-3.0-or-later; see COPYING. */
"use strict";
var childProcess = require("child_process");
var crypto = require("crypto");
var fs = require("fs");
var https = require("https");
var path = require("path");
var url = require("url");
var PACKAGE_SHA256 = "d10bf3c753551d7c72fb7a92b20fcd2317e502a220ac668ba8e76f6ea78b363c";
var FILES = ["autoroot.sh", "package.json", "main.js", "luna-helper.js", "hbchannel-startup.sh", "hbchannel.ipk"];

function parseEndpoint(endpoint) {
  // Keep compatibility with older TV Node runtimes, but allow only an
  // unambiguous ASCII HTTPS URL before invoking the legacy URL parser.
  if (typeof endpoint !== 'string' || !/^https:\/\/[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?\/[a-f0-9]{64}\/result$/.test(endpoint)) throw new Error('invalid HTTPS receipt endpoint');
  var parsed = url.parse(endpoint);
  if (parsed.port && (+parsed.port < 1 || +parsed.port > 65535)) throw new Error('invalid receipt port');
  return parsed;
}

function validateFiles(directory, manifest) {
  if (!manifest || !manifest.sha256 || manifest.package_sha256 !== PACKAGE_SHA256) throw new Error("invalid package manifest");
  if (!Array.isArray(manifest.files) || manifest.files.slice().sort().join(";") !== FILES.slice().sort().join(";")) throw new Error("unexpected manifest file list");
  FILES.forEach(function (name) {
    var target = path.join(directory, name), stat = fs.lstatSync(target);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 8 * 1024 * 1024) throw new Error("unsafe staged file");
    var actual = crypto.createHash("sha256").update(fs.readFileSync(target)).digest("hex");
    if (actual !== manifest.sha256[name] || (name === "hbchannel.ipk" && actual !== PACKAGE_SHA256)) throw new Error("staged file SHA-256 mismatch");
  });
}

function execute(script, callback) {
  var proc = childProcess.spawn('/bin/bash', [script], {detached: true, stdio: ['ignore', 'pipe', 'pipe']});
  var chunks = [], size = 0, failed = false, finished = false, killTimer;
  function terminate() {
    if (!proc.pid) return;
    try { process.kill(-proc.pid, 'SIGTERM'); } catch (ignored) {}
    if (!killTimer) killTimer = setTimeout(function () {
      try { process.kill(-proc.pid, 'SIGKILL'); } catch (ignored) {}
    }, 2000);
  }
  var timer = setTimeout(function () { failed = true; terminate(); }, 150000);
  function collect(chunk) {
    size += chunk.length;
    if (size > 512 * 1024) { failed = true; terminate(); return; }
    chunks.push(chunk);
  }
  proc.stdout.on('data', collect); proc.stderr.on('data', collect);
  function finish(err, code) {
    if (finished) return;
    finished = true; clearTimeout(timer); clearTimeout(killTimer);
    if (err || failed || code !== 0) {
      // Ensure detached descendants cannot keep changing TV state after failure.
      if (proc.pid) { try { process.kill(-proc.pid, 'SIGKILL'); } catch (ignored) {} }
    }
    try {
      var logPath = path.join(path.dirname(script), 'installer-' + crypto.randomBytes(8).toString('hex') + '.log');
      var fd = fs.openSync(logPath, 'wx', 384);
      try { fs.writeFileSync(fd, Buffer.concat(chunks)); } finally { fs.closeSync(fd); }
    } catch (logError) { err = logError; }
    callback(err || (failed || code !== 0 ? new Error('installer terminated unsuccessfully') : null));
  }
  proc.on('error', function (err) { finish(err); });
  proc.on('close', function (code) { finish(null, code); });
}

function report(endpoint, result) {
  var parsed = parseEndpoint(endpoint), body = JSON.stringify(result), finished = false;
  function finish(code) { if (finished) return; finished = true; process.exitCode = code; }
  var req = https.request({hostname: parsed.hostname, port: parsed.port || 443, path: parsed.path,
    method: "POST", rejectUnauthorized: true, secureProtocol: "TLSv1_2_method",
    headers: {"Content-Type": "application/json", "Content-Length": Buffer.byteLength(body)}}, function (res) {
    res.resume(); finish(res.statusCode === 204 && result.ok ? 0 : 1);
  });
  req.setTimeout(10000, function () { req.abort(); finish(1); });
  req.on("error", function () { console.error("Could not deliver authenticated installer result; inspect TV state"); finish(1); });
  req.end(body);
}

function run() {
  var script = process.argv[2], encoded = process.argv[3], endpoint = process.argv[4];
  var result = {ok: false, root_verified: false, phase: "validation", error: "validation failed"};
  try {
    if (!script || path.basename(script) !== "autoroot.sh" || !/^\/media\/internal\/downloads\/slopbro-[a-f0-9]{64}$/.test(path.dirname(script))) throw new Error("unexpected staging directory");
    if (!encoded || encoded.length > 16384) throw new Error("invalid manifest length");
    var decoded = Buffer.from ? Buffer.from(encoded, "base64") : new Buffer(encoded, "base64");
    var manifest = JSON.parse(decoded.toString("utf8"));
    var parsed = parseEndpoint(endpoint);
    if (parsed.protocol !== "https:" || parsed.pathname !== "/" + manifest.session + "/result" || path.basename(path.dirname(script)) !== "slopbro-" + manifest.session) throw new Error("receipt does not match this session");
    var directoryStat = fs.lstatSync(path.dirname(script));
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) throw new Error("unsafe staging directory");
    validateFiles(path.dirname(script), manifest);
    fs.chownSync(path.dirname(script), 0, 0);
    fs.chmodSync(path.dirname(script), 448);
    result.phase = "installation";
    execute(script, function (err) {
      try {
        if (err) throw err;
        var state = JSON.parse(fs.readFileSync(path.join(path.dirname(script), "install-state.json"), "utf8"));
        if (state.success !== true || state.root_verified !== true) throw new Error("installer root verification was not successful");
        report(endpoint, {ok: true, root_verified: true, phase: "complete"});
      } catch (error) {
        console.error(error.message);
        result.error = "Installation failed; inspect session state and installer logs before retrying";
        try { report(endpoint, result); } catch (reportError) { console.error(reportError.message); process.exitCode = 1; }
      }
    });
    return;
  } catch (err) {
    result.error = "Installer failed; inspect the session install-state.json and local logs before retrying";
    console.error(err.message);
  }
  try { report(endpoint, result); }
  catch (err) { console.error(err.message); process.exitCode = 1; }
}

module.exports = {run: run, validateFiles: validateFiles, report: report, execute: execute};
