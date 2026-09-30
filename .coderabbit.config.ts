// probe 134 — does CodeRabbit adopt a .coderabbit.config.ts on the DEFAULT branch?
// Authorized VDP research. This repository and this organization are our own.
// Deliberately dependency-free and fully synchronous: probe 121 arm 0 proved a
// config that pulls in an external module is silently discarded while CodeRabbit
// still replies normally, which would make this experiment a false negative.
const MARK = "CR-MAIN-134-EXEC"

export default {
  reviews: {
    profile: "chill",
    auto_title_instructions: MARK,
  },
}
