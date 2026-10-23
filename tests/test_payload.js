/* Offline page, parser, filesystem and installer watchdog regressions. */
"use strict";
const assert = require("assert");
const crypto = require("crypto");
const events = require("events");
const fs = require("fs");
const os = require("os");
const path = require("path");
const vm = require("vm");
const root = path.join(__dirname, "..");
const helper = require("../wwwroot/luna-helper.js");
const hash = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const session = "a".repeat(64);
const ipkHash = "d10bf3c753551d7c72fb7a92b20fcd2317e502a220ac668ba8e76f6ea78b363c";
const files = ["autoroot.sh", "hbchannel-startup.sh", "hbchannel.ipk", "luna-helper.js", "main.js", "package.json"];
let count = 0;
function test(name, fn) { fn(); count++; console.log("ok - " + name); }

test("JSON parser handles chunks, pretty output, escapes and multiple objects", () => {
  const values = [], feed = helper.decodeObjects(x => values.push(x));
  const text = JSON.stringify({x: 'braces } [ and quote " and slash \\', nested: [{a: 1}]}, null, 2);
  for (const c of text + "\n" + '{"returnValue":true}') feed(c);
  assert.strictEqual(values.length, 2);
  assert.strictEqual(values[0].nested[0].a, 1);
  assert.strictEqual(values[1].returnValue, true);
  assert.throws(() => helper.decodeObjects(() => {})("garbage"));
  assert.throws(() => helper.decodeObjects(() => {})('{"x":"' + "a".repeat(1024 * 1024)));
});
test("installer needs a structured terminal status and the expected package", () => {
  assert.strictEqual(helper.classifyInstall({status: "installed"}), false);
  assert.strictEqual(helper.classifyInstall({statusValue: 30, details: {packageId: "org.webosbrew.hbchannel"}}), true);
  for (const value of [
    {returnValue: false, status: "not installed"}, {statusValue: 25},
    {statusValue: 30, details: {packageId: "org.webosbrew.hbchannel", errorCode: 0}},
    {statusValue: 30, details: {packageId: "other"}}, {statusValue: 30}, null
  ]) assert.throws(() => helper.classifyInstall(value));
});

function page(options = {}) {
  const elements = {status: {}, error: {}}, calls = [], receipts = [], timers = new Map();
  let timerId = 0;
  const manifest = {session, files: files.slice(), package_sha256: ipkHash, sha256: {}};
  files.forEach(file => manifest.sha256[file] = file === "hbchannel.ipk" ? ipkHash : "b".repeat(64));
  if (options.badManifest) manifest.sha256["hbchannel.ipk"] = "c".repeat(64);
  function XHR() {}
  XHR.prototype.open = function(method, target) { this.method = method; this.target = target; };
  XHR.prototype.setRequestHeader = function() {};
  XHR.prototype.send = function(body) {
    if (this.method === "POST") { receipts.push(JSON.parse(body)); return; }
    this.status = options.manifest404 ? 404 : 200;
    this.responseText = JSON.stringify(manifest); this.onload();
  };
  function Bridge() {}
  Bridge.prototype.cancel = function() {};
  Bridge.prototype.call = function(uri, text) {
    const payload = JSON.parse(text); calls.push({uri, payload});
    if (uri.endsWith("/download")) {
      if (options.stall) return;
      if (!options.combined) {
        this.onservicecallback('{"returnValue":true,"subscribed":true}');
        this.onservicecallback('{"completed":false,"amountReceived":1,"amountTotal":5}');
      }
      this.onservicecallback(JSON.stringify({returnValue: !options.rejected, completed: true,
        httpStatus: options.httpError ? 404 : 200, aborted: false, interrupted: false}));
      if (options.duplicate) this.onservicecallback('{"completed":true,"httpStatus":200}');
    } else this.onservicecallback(JSON.stringify({returnValue: !options.launchError}));
  };
  const context = {
    document: {getElementById: key => elements[key]},
    location: {protocol: options.http ? "http:" : "https:", origin: "https://payload.example:8443",
      pathname: "/" + session + "/index.html", search: "?fake-service-path=%2Fusr%2Fpalm%2Fservices%2Fcom.palm.service.devmode"},
    XMLHttpRequest: XHR,
    btoa: value => Buffer.from(value, "binary").toString("base64"),
    setTimeout: (fn, delay) => { timers.set(++timerId, {fn, delay}); return timerId; },
    clearTimeout: id => timers.delete(id)
  };
  if (!options.noBridge) context.PalmServiceBridge = Bridge;
  const script = fs.readFileSync(path.join(root, "wwwroot/index.html"), "utf8").match(/<script>([\s\S]*?)<\/script>/)[1];
  vm.runInNewContext(script, context);
  return {elements, calls, receipts, timers};
}
test("page accepts combined completion and progress updates without duplicate launches", () => {
  for (const options of [{combined: true}, {}, {duplicate: true}]) {
    const output = page(options);
    assert.strictEqual(output.calls.length, 7);
    assert.strictEqual(output.receipts.length, 0);
    const downloads = output.calls.filter(c => c.uri.endsWith("/download"));
    assert.strictEqual(downloads.length, 6);
    downloads.forEach(d => {
      assert.ok(d.payload.target.startsWith("https://"));
      assert.strictEqual(d.payload.targetDir, "/media/internal/downloads/slopbro-" + session);
    });
    const args = output.calls[6].payload.inputParams.split(" ");
    assert.ok(args.includes("/media/internal/downloads/slopbro-" + session + "/autoroot.sh"));
    const decoded = JSON.parse(Buffer.from(args[args.length - 2], "base64").toString());
    assert.strictEqual(decoded.session, session);
    assert.ok(output.elements.status.textContent.includes("Wait for a verified result"));
  }
});
test("page fails closed for missing bridge, HTTP errors, rejected downloads and manifest errors", () => {
  for (const options of [{noBridge: true}, {httpError: true}, {rejected: true}, {badManifest: true}, {manifest404: true}]) {
    const output = page(options);
    assert.strictEqual(output.calls.filter(c => c.uri.endsWith("/run")).length, 0);
    assert.strictEqual(output.receipts.length, 1);
    assert.strictEqual(output.receipts[0].ok, false);
    assert.ok(output.elements.error.textContent);
  }
});
test("page refuses HTTP before loading any manifest or native bridge", () => {
  const output = page({http: true});
  assert.strictEqual(output.calls.length, 0);
  assert.ok(output.elements.error.textContent.includes("HTTPS"));
});
test("page has a finite download deadline and reports service-launch failure", () => {
  const output = page({stall: true});
  [...output.timers.values()][0].fn();
  assert.strictEqual(output.receipts[0].ok, false);
  assert.strictEqual(page({launchError: true}).receipts[0].ok, false);
});

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "slopbro-js-test-"));
try {
  const virtual = "/media/internal/downloads/slopbro-" + session;
  const remap = target => typeof target === "string" && target.startsWith(virtual) ? temporary + target.slice(virtual.length) : target;
  const packageBytes = Buffer.from("inert fixture IPK");
  const manifest = {session, files, package_sha256: hash(packageBytes), sha256: {}};
  files.forEach(file => {
    const bytes = file === "hbchannel.ipk" ? packageBytes : Buffer.from("inert " + file);
    fs.writeFileSync(path.join(temporary, file), bytes);
    manifest.sha256[file] = hash(bytes);
  });
  const source = fs.readFileSync(path.join(root, "wwwroot/main.js"), "utf8").replace(ipkHash, hash(packageBytes));
  function moduleFixture() {
    const posts = [], children = [], timers = new Map(), signals = [];
    let timerId = 0;
    const fakeFs = Object.assign({}, fs);
    for (const method of ["lstatSync", "readFileSync", "chmodSync", "openSync"]) {
      fakeFs[method] = function(target, ...rest) { return fs[method](remap(target), ...rest); };
    }
    fakeFs.chownSync = function() {};
    const fakeProcess = {argv: ["node", "main.js", virtual + "/autoroot.sh",
      Buffer.from(JSON.stringify(manifest)).toString("base64"), "https://payload.example/" + session + "/result"],
      kill: (pid, signal) => signals.push({pid, signal})};
    const fakeHttps = {request: (options, onResponse) => {
      const request = new events.EventEmitter();
      request.setTimeout = function() {}; request.abort = function() {};
      request.end = body => { posts.push({options, body: JSON.parse(body)}); onResponse({statusCode: 204, resume() {}}); };
      return request;
    }};
    const childProcess = {spawn: (command, args, options) => {
      assert.strictEqual(command, "/bin/bash");
      const child = new events.EventEmitter();
      Object.assign(child, {stdout: new events.EventEmitter(), stderr: new events.EventEmitter(), pid: 12345});
      children.push({child, command, args, options}); return child;
    }};
    const context = {module: {exports: {}}, Buffer, console: {error() {}}, process: fakeProcess,
      require: name => ({fs: fakeFs, https: fakeHttps, child_process: childProcess}[name] || require(name)),
      setTimeout: (fn, delay) => { timers.set(++timerId, {fn, delay}); return timerId; },
      clearTimeout: id => timers.delete(id)};
    vm.runInNewContext(source, context);
    return {api: context.module.exports, posts, children, timers, signals, process: fakeProcess};
  }
  test("root wrapper rejects tampered files and symlinks before spawning Bash", () => {
    const fixture = moduleFixture();
    fs.writeFileSync(path.join(temporary, "main.js"), "tampered");
    fixture.api.run();
    assert.strictEqual(fixture.children.length, 0);
    assert.strictEqual(fixture.posts[0].body.ok, false);
    fs.writeFileSync(path.join(temporary, "main.js"), "inert main.js");
    fs.renameSync(path.join(temporary, "main.js"), path.join(temporary, "original"));
    fs.symlinkSync(path.join(temporary, "original"), path.join(temporary, "main.js"));
    assert.throws(() => fixture.api.validateFiles(virtual, manifest));
    fs.unlinkSync(path.join(temporary, "main.js"));
    fs.renameSync(path.join(temporary, "original"), path.join(temporary, "main.js"));
  });
  test("root wrapper requires installer success and a successful root check", () => {
    for (const success of [true, false]) {
      const fixture = moduleFixture(); fixture.api.run();
      assert.strictEqual(fixture.children.length, 1);
      fs.writeFileSync(path.join(temporary, "install-state.json"), JSON.stringify({success, root_verified: success}));
      fixture.children[0].child.stdout.emit("data", Buffer.from("inert installer output"));
      fixture.children[0].child.emit("close", 0);
      assert.strictEqual(fixture.posts[0].body.ok, success);
      assert.strictEqual(fixture.posts[0].options.rejectUnauthorized, true);
      assert.strictEqual(fixture.posts[0].options.secureProtocol, "TLSv1_2_method");
    }
  });
  test("root wrapper preserves child exit failure despite a stale success file", () => {
    const fixture = moduleFixture(); fixture.api.run();
    fs.writeFileSync(path.join(temporary, "install-state.json"), '{"success":true,"root_verified":true}');
    fixture.children[0].child.emit("close", 1);
    assert.strictEqual(fixture.posts[0].body.ok, false);
  });
  test("watchdog terminates the entire child process group and reports failure", () => {
    const fixture = moduleFixture(); fixture.api.run();
    [...fixture.timers.values()].find(t => t.delay === 150000).fn();
    [...fixture.timers.values()].find(t => t.delay === 2000).fn();
    assert.deepStrictEqual(fixture.signals.map(s => [s.pid, s.signal]), [[-12345, "SIGTERM"], [-12345, "SIGKILL"]]);
    fixture.children[0].child.emit("close", null);
    assert.strictEqual(fixture.posts[0].body.ok, false);
  });
  test("receipt sender rejects plaintext and mismatched capability paths", () => {
    const fixture = moduleFixture();
    for (const endpoint of ["http://payload.example/" + session + "/result", "https://payload.example/result"]) {
      assert.throws(() => fixture.api.report(endpoint, {ok: true}));
    }
    assert.strictEqual(fixture.posts.length, 0);
  });
  test("installer output logs are created with private permissions", () => {
    const logs = fs.readdirSync(temporary).filter(file => /^installer-.*\.log$/.test(file));
    assert.ok(logs.length > 0);
    logs.forEach(file => assert.strictEqual(fs.statSync(path.join(temporary, file)).mode & 511, 384));
  });
} finally {
  fs.rmSync(temporary, {recursive: true, force: true});
}
console.log(count + " JavaScript security regressions passed");
