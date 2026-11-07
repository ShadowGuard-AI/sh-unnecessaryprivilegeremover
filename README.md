# sh-UnnecessaryPrivilegeRemover
Analyzes one target directory tree for executables with the setuid or setgid bits set, and removes those bits from files that pass the test below only when --apply is given. The default run is a dry run: it prints the full candidate list and changes nothing. The --dry-run flag remains as an explicit spelling of that default.

The real test, stated plainly: a file keeps its bits when a process with its path was seen running during the monitor window. Nothing about process ancestry or process creation is measured. Warning: short windows strip rarely run helpers, because a helper that runs only at login, on a schedule, or on demand outside the window will not be seen and will be listed as a candidate.

A target root is required, given with --root or by the root key in the config file: a run with neither refuses at exit 1 and scans nothing. A root that is not an existing directory also refuses at exit 1 and scans nothing. Passing --dry-run and --apply together is a conflict and refuses at exit 1 with no scan and no changes. When monitoring raises an error or collects zero processes, the run aborts at exit 1 with no removals, in dry run and apply modes alike. Failed removals are counted, the failed paths are named, and a run with any failed removal exits 1 with the failure count as the final line.

The config file is optional, given with --config, and is honoured when present. Documented keys: keep_paths (a list of paths never stripped), root (used when no command line target is given), and monitor_seconds. A config that is named but fails to load exits 1. When no config is present, the run proceeds on command line values and logs that no config is in effect.

## Install
```
git clone https://github.com/ShadowGuard-AI/sh-unnecessaryprivilegeremover
cd sh-unnecessaryprivilegeremover
pip install -r requirements.txt
```

## Usage
`python3 main.py --root <directory> --monitor-time 1`
Add `--apply` to remove the listed bits. Without it the run is a dry run and changes nothing.

## Parameters
- `-h`: Show help message and exit
- `--root`: Target root directory to scan. Required unless the config sets root.
- `--config`: Path to the optional YAML configuration file.
- `--dry-run`: Perform a dry run without actually removing any privileges. This is the default.
- `--apply`: Actually remove privileges from the listed candidates.
- `--monitor-time`: Time in seconds to monitor processes. Default is 60 seconds, or monitor_seconds from the config.

## License
MIT License. See [LICENSE](LICENSE).
