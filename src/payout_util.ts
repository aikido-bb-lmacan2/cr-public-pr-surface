// probe 112: trivial, gives the PR a real code diff to review.
export function total(items: number[]): number {
  return items.reduce((a, b) => a + b, 0)
}
