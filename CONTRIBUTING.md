# Contributing to RAQIB

Thanks for considering a contribution — bug reports, new detection rules, translations,
and new tools are all welcome.

## Before You Start

- Check open [Issues](https://github.com/Ali5667/RAQIB-Defensive-Security-Toolkit/issues)
  and [Pull Requests](https://github.com/Ali5667/RAQIB-Defensive-Security-Toolkit/pulls)
  to avoid duplicate work.
- For a significant change (new tool, new language, architecture change), open an issue
  first to discuss the approach before writing code.

## Ways to Contribute

- **Bug reports** — open an issue with your OS, Bash version, the command you ran, and
  what you expected vs. what happened.
- **New YARA-lite detection rules** — add lines in `name|weight|regex` format to
  `tools/malware/rules/webshell_lite.rules`, and add a matching labeled sample (malicious
  and/or clean) to `tests/corpus/` so `tests/run_accuracy_eval.sh` can validate it.
- **New or improved translations** — `modules/lang.sh` holds every language's strings as
  `STR_<LANG>[key]="..."`. Keep the same key set as `STR_EN` (see the file for the full
  list) and match existing tone/terminology.
- **New tools** — follow the existing structure under `tools/<category>/`, wire the menu
  entry into the matching file under `modules/`, and add translation strings for every
  language you can (English + Arabic at minimum).

## Code Style

- Pure Bash + POSIX utilities where possible; Python3 only when Bash genuinely can't do
  the job cleanly (e.g. the entropy calculation).
- No dependency on external security tools (Nmap, Wireshark, etc.) — this is a project
  constraint, not a preference.
- Match the existing quoting/error-handling style in the file you're editing.

## Testing Your Change

```bash
bash -n path/to/your_script.sh          # syntax check
bash tests/run_accuracy_eval.sh          # if you touched detection logic
```

## Submitting

1. Fork the repo, create a branch (`feature/your-change` or `fix/issue-123`).
2. Keep commits focused — one logical change per commit.
3. Open a pull request describing what changed and why, and reference any related issue.

By contributing, you agree your contribution is licensed under the same
[MIT License](LICENSE) as the rest of the project.
