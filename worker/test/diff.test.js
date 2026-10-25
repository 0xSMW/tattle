import { test } from "node:test";
import assert from "node:assert/strict";
import { diffSections } from "../src/diff.js";

const base = {
	accounts: "admin: bruno root\nuser: bruno 501",
	ssh: "remote-login: Off",
	persistence: "abc /Library/LaunchDaemons/a.plist",
	posture: "filevault: FileVault is On.\nfirewall: enabled",
	listening: "Dropbox bruno *:17500\nbb bruno 127.0.0.1:38886",
	packages: "Foo.app 1.0",
};

test("no change, no findings", () => {
	assert.deepEqual(diffSections(base, { ...base }), []);
});

test("new admin, ssh key and launch daemon alert", () => {
	const after = {
		...base,
		accounts: "admin: bruno evil root\nuser: bruno 501",
		ssh: "remote-login: Off\nroot SHA256:xyz key",
		persistence: base.persistence + "\ndef /Library/LaunchDaemons/evil.plist",
	};
	const out = diffSections(base, after);
	assert.equal(out.length, 3);
	assert.ok(out.some((l) => l.includes("evil.plist")));
});

test("posture regression alerts", () => {
	const out = diffSections(base, { ...base, posture: "filevault: FileVault is Off.\nfirewall: enabled" });
	assert.deepEqual(out, ["~ posture: filevault: FileVault is Off."]);
});

test("loopback and port churn are ignored; new exposed process alerts", () => {
	const quiet = { ...base, listening: "Dropbox bruno *:17501\nbb bruno 127.0.0.1:40000\nnode bruno 127.0.0.1:3000" };
	assert.deepEqual(diffSections(base, quiet), []);
	const loud = { ...base, listening: base.listening + "\nnc bruno *:4444" };
	assert.deepEqual(diffSections(base, loud), ["+ listening: nc now accepts connections from the network"]);
});

test("linux ss lines parse the process name", () => {
	const before = { ...base, listening: "tcp 0.0.0.0:22 sshd" };
	const after = { ...base, listening: "tcp 0.0.0.0:22 sshd\ntcp [::]:8080 python3\ntcp 127.0.0.1:5432 postgres" };
	assert.deepEqual(diffSections(before, after), ["+ listening: python3 now accepts connections from the network"]);
});

test("package changes never alert", () => {
	assert.deepEqual(diffSections(base, { ...base, packages: "Foo.app 2.0\nBar.app 1.0" }), []);
});

import { plantScript } from "../src/canaries.js";

test("plant script strips shell metacharacters from token values", () => {
	const evil = { aws_access_key_id: "AKIA$(rm -rf ~)", aws_secret_access_key: "x`y`", region: "us-east-2" };
	const script = plantScript({ aws: evil, envFile: evil, dns: { hostname: "abc.canarytokens.com;reboot" } });
	assert.ok(!script.includes("$(rm"));
	assert.ok(!script.includes("`y`"));
	assert.ok(script.includes("HostName abc.canarytokens.comreboot"));
});
