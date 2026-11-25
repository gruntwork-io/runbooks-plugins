---
name: progressive-disclosure
description: Use when a function mixes levels of abstraction, or when deciding whether to extract a private helper.
---

# Progressive disclosure

Detail the caller cannot act on belongs one level down.

## The test

Can a reader follow the caller without opening the helper?

- Yes. The extraction hid something. Keep it.
- No. You moved code without hiding it. Rename it, or inline it back.

A section comment you were about to write is the name of a helper you have not
written yet. Extract it and delete the comment.

## Do not

- **Reuse is not the bar.** One call site is enough if the name hides detail.
- Extractions needing the caller's locals, or five parameters. Not a separate concern.
- Steps that are the logic. If the job is A then B then C, the steps are the abstraction.
- Length alone. Sixty lines at one altitude beats twenty across four empty names.
- Guards that return from the caller. A Rust helper cannot return for its caller.
