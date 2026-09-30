// probe 112 H1 base-arm PR: this branch carries NO config, so the resolved config must
// come from the base (default) branch, where probe 112 placed the base control.
export function add(a: number, b: number): number {
  return a + b
}
