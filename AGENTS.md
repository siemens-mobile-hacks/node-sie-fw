# Project Guidelines

AGENTS.md contains only general, lasting project rules. Do not add task plans, specifications, acceptance criteria, or requirements for individual features. Record user-established conventions only when they apply across the project.

## Development

- Follow the surrounding code, architecture, naming, formatting, and error handling.
- Choose the simplest complete solution. Reuse existing utilities; avoid redundant checks, wrappers, abstractions, and boilerplate comments.
- Do not add type assertions, runtime checks, validation, or fallbacks "just in case." Each one must address a concrete type constraint, possible runtime state, or external input boundary.
- Fix underlying causes. Do not retain duplicate implementations or compatibility code for unshipped behavior.
- Keep changes within the task scope and preserve unrelated behavior and public interfaces.
- Only use pnpm for package manipulations. Use existing dependencies where possible; obtain explicit user approval before installing new ones.
- Run relevant checks and fix errors introduced by the changes.

## Code Style

- Use camelCase filenames, except for filenames required by tools or established standards.
- Use `undefined` instead of `null` wherever possible. Use `null` only when required by an API.
- Use optional parameter syntax (`value?: Type`) when callers may omit a trailing argument. Use `value: Type | undefined` only when the argument position is required.
- Use explicit named imports instead of namespace imports.
- In multiline ternaries, place `?` and `:` at the end of the preceding line.
- Do not use nested ternary expressions. Use `if`, `else`, or `switch` instead.
- Use braces for `if` statements with an `else` branch or a multiline body.
