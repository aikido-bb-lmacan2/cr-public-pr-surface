// probe 112: intentionally trivial, gives the PR a real diff to review.
export function total(items: number[]): number {
  return items.reduce((a, b) => a + b, 0)
}
