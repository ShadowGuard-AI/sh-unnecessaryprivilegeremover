# sh-UnnecessaryPrivilegeRemover
Analyzes a Linux system for executables with the setuid or setgid bits set, and automatically removes these bits where they are deemed unnecessary based on observed system behavior and process ancestry. Utilizes `psutil` and `subprocess` to monitor process creation and execution to identify if the elevated privileges are actually being used. - Focused on Tools for automating system hardening and configuration. This category provides utilities for generating secure configuration files (e.g., for web servers, databases, operating systems) from templates based on security best practices and compliance standards. Leverages YAML and templating to create customized hardening guides.

## Install
`git clone https://github.com/ShadowStrikeHQ/sh-unnecessaryprivilegeremover`

## Usage
`./sh-unnecessaryprivilegeremover [params]`

## Parameters
- `-h`: Show help message and exit
- `--config`: Path to the YAML configuration file.
- `--dry-run`: Perform a dry run without actually removing any privileges.
- `--monitor-time`: Time in seconds to monitor process creation and execution. Default is 60 seconds.

## License
Copyright (c) ShadowStrikeHQ
