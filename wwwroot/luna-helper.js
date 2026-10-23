/* SlopBro: bounded, structured Luna helpers. AGPL-3.0-or-later. */
"use strict";
var childProcess = require("child_process");

function decodeObjects(onObject) {
  var text = "", start = -1, depth = 0, quoted = false, escaped = false;
  return function (chunk) {
    for (var i = 0; i < chunk.length; i++) {
      var c = chunk[i];
      if (start === -1) {
        if (/\s/.test(c)) continue;
        if (c !== "{") throw new Error("non-JSON Luna response");
        start = 0;
      }
      text += c;
      if (text.length > 1024 * 1024) throw new Error("Luna response exceeds limit");
      if (quoted) {
        if (escaped) escaped = false;
        else if (c === "\\") escaped = true;
        else if (c === '"') quoted = false;
      } else if (c === '"') quoted = true;
      else if (c === "{" || c === "[") depth++;
      else if (c === "}" || c === "]") depth--;
      if (depth === 0 && !quoted) {
        var value = JSON.parse(text);
        text = ""; start = -1;
        onObject(value);
      }
    }
  };
}

function classifyInstall(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid installer response");
  if (value.returnValue === false || value.status === "failed" || value.statusValue === 25 ||
      (value.details && value.details.errorCode !== undefined)) {
    throw new Error("package installer reported failure");
  }
  if (value.statusValue === 30) {
    if (!value.details || value.details.packageId !== "org.webosbrew.hbchannel") {
      throw new Error("installer returned an unexpected package identity");
    }
    return true;
  }
  return false;
}

function request(mode, ipk) {
  var install = mode === "install", uri, payload;
  if (install) {
    uri = "luna://com.webos.appInstallService/dev/install";
    payload = {id: "com.ares.defaultName", ipkUrl: ipk, subscribe: true};
  } else if (mode === "check-devmode") {
    uri = "luna://com.webos.applicationManager/listApps"; payload = {};
  } else if (mode === "verify-root") {
    uri = "luna://org.webosbrew.hbchannel.service/checkRoot"; payload = {};
  } else throw new Error("unknown Luna helper mode");
  var args = ["-w", install ? "30000" : "5000"];
  args = args.concat(install ? ["-i"] : ["-n", "1"]);
  args.push(uri, JSON.stringify(payload));
  var proc = childProcess.spawn("luna-send", args, {stdio: ["ignore", "pipe", "pipe"]});
  var finished = false, closed = false, killTimer;
  var timer = setTimeout(function () { finish(new Error("Luna request timed out")); }, install ? 35000 : 8000);
  function finish(error) {
    if (finished) return;
    finished = true; clearTimeout(timer);
    proc.kill("SIGTERM");
    if (!closed) killTimer = setTimeout(function () { proc.kill("SIGKILL"); }, 2000);
    if (error) process.stderr.write(error.message + "\n");
    process.exitCode = error ? 1 : 0;
  }
  var feed = decodeObjects(function (value) {
    if (finished) return;
    if (install) { if (classifyInstall(value)) finish(null); return; }
    if (!value || value.returnValue !== true) throw new Error("Luna request was rejected");
    if (mode === "check-devmode") {
      if (!Array.isArray(value.apps)) throw new Error("could not establish Developer Mode app state");
      if (value.apps.some(function (app) { return !app || typeof app.id !== "string"; })) throw new Error("invalid app list");
      if (value.apps.some(function (app) { return app.id === "com.palmdts.devmode"; })) {
        throw new Error("uninstall LG Developer Mode before installing persistent root");
      }
    }
    finish(null);
  });
  proc.stdout.setEncoding("utf8");
  proc.stdout.on("data", function (chunk) { try { feed(chunk); } catch (err) { finish(err); } });
  proc.stderr.on("data", function () {});
  proc.on("error", finish);
  proc.on("close", function () { closed = true; clearTimeout(killTimer); if (!finished) finish(new Error("Luna exited without a terminal result")); });
  process.on("SIGTERM", function () { finish(new Error("Luna helper interrupted")); });
}

module.exports = {decodeObjects: decodeObjects, classifyInstall: classifyInstall};
if (require.main === module) {
  try { request(process.argv[2], process.argv[3]); }
  catch (err) { process.stderr.write(err.message + "\n"); process.exitCode = 1; }
}
