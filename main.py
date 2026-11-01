import argparse
import logging
import os
import subprocess
import psutil
import yaml
import time
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PrivilegeRemoverError(Exception):
    """Custom exception class for privilege remover errors."""
    pass


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Analyzes and removes unnecessary setuid/setgid bits from executables."
    )

    parser.add_argument(
        "--root",
        type=str,
        default=None,
        help="Target root directory to scan. Required, unless the config file sets root. A run with no target root refuses and scans nothing."
    )
    parser.add_argument(
        "--config",
        type=str,
        help="Path to the optional YAML configuration file. Honoured keys: keep_paths, root, and monitor_seconds.",
        default=None
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform a dry run without actually removing any privileges. This is the default; the flag is an explicit spelling of it."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually remove privileges from the listed candidates. Without this flag the run is a dry run and changes nothing."
    )
    parser.add_argument(
        "--monitor-time",
        type=int,
        default=None,
        help="Time in seconds to monitor processes. A file keeps its bits when a process with its path was seen running during the monitor window. Default is 60 seconds, or monitor_seconds from the config."
    )


    return parser

def load_config(config_file):
    """
    Loads configuration from a YAML file.
    Args:
        config_file (str): Path to the YAML configuration file.
    Returns:
        dict: Configuration dictionary.
    Raises:
        PrivilegeRemoverError: If the configuration file is invalid or cannot be loaded.
    """
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
            if not isinstance(config, dict):
                raise PrivilegeRemoverError("Configuration file must contain a dictionary.")
            return config
    except FileNotFoundError:
        raise PrivilegeRemoverError(f"Configuration file not found: {config_file}")
    except yaml.YAMLError as e:
        raise PrivilegeRemoverError(f"Error parsing YAML file: {e}")
    except Exception as e:
        raise PrivilegeRemoverError(f"Failed to load configuration: {e}")

def find_setuid_setgid_files(root_dir="/"):
    """
    Finds all files with setuid or setgid bits set under a given directory.
    Args:
        root_dir (str): The root directory to search from. Defaults to "/".
    Returns:
        list: A list of tuples, where each tuple contains the file path and its permissions.
    """
    setuid_setgid_files = []
    try:
        for root, _, files in os.walk(root_dir):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    stat_info = os.stat(filepath)
                    if stat_info.st_mode & (0o4000 | 0o2000):  # Check for setuid or setgid
                        setuid_setgid_files.append((filepath, stat_info.st_mode))
                except OSError as e:
                    logging.warning(f"Could not stat {filepath}: {e}")
                    continue
    except OSError as e:
        logging.error(f"Error walking directory {root_dir}: {e}")
    return setuid_setgid_files


def monitor_processes(duration):
    """
    Monitors process creation and execution for a specified duration.
    Args:
        duration (int): The duration in seconds to monitor processes.
    Returns:
        tuple: (set of executable paths seen running during the window,
        True when monitoring raised an error).
    """
    created_processes = set()
    start_time = time.time()
    failed = False
    logging.info(f"Monitoring processes for {duration} seconds...")

    try:
        while time.time() - start_time < duration:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    exe = proc.info['exe']
                    if exe:
                        created_processes.add(exe)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    logging.warning(f"Error getting process info: {e}")
                    continue
            time.sleep(0.1)  # Check frequently without consuming too much CPU
    except Exception as e:
        failed = True
        logging.error(f"Error during process monitoring: {e}")
    finally:
        logging.info("Process monitoring completed.")
    return created_processes, failed


def check_privilege_usage(filepath, monitored_processes):
    """
    Checks if a given file with setuid/setgid bits is used by any of the monitored processes.
    Args:
        filepath (str): The path to the file.
        monitored_processes (set): A set of executable paths of monitored processes.
    Returns:
        bool: True if the file is used, False otherwise.
    """
    return filepath in monitored_processes

def remove_privileges(filepath, dry_run=False):
    """
    Removes setuid and setgid bits from a file.
    Args:
        filepath (str): The path to the file.
        dry_run (bool): If True, only prints the command without executing it.
    """
    try:
        if not dry_run:
            subprocess.run(['chmod', 'a-s', filepath], check=True) # Use subprocess.run with check=True
            logging.info(f"Removed setuid/setgid bits from: {filepath}")
        else:
            logging.info(f"[Dry Run] Would remove setuid/setgid bits from: {filepath}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to remove privileges from {filepath}: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False


def main():
    """
    Main function to execute the privilege removal process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    config = {}
    if args.config:
        try:
            config = load_config(args.config)
        except PrivilegeRemoverError as e:
            logging.error(e)
            sys.exit(1)
    else:
        logging.info("No config file in effect.")

    # Target root: the command line wins, then the config. A run with
    # neither refuses plainly and scans nothing.
    root = args.root or config.get("root")
    if not root:
        logging.error("No target root given. Refusing to run.")
        print("No target root given. Refusing to run.")
        sys.exit(1)

    if args.monitor_time is not None:
        monitor_time = args.monitor_time
    elif config.get("monitor_seconds") is not None:
        monitor_time = config.get("monitor_seconds")
    else:
        monitor_time = 60

    # Validate monitor_time
    if not isinstance(monitor_time, int) or monitor_time <= 0:
        logging.error("Monitor time must be a positive integer.")
        sys.exit(1)

    keep_paths = set()
    for entry in config.get("keep_paths") or []:
        keep_paths.add(os.path.abspath(str(entry)))
        keep_paths.add(str(entry))

    apply_mode = bool(args.apply)

    try:
        setuid_setgid_files = find_setuid_setgid_files(root)
        logging.info(f"Found {len(setuid_setgid_files)} files with setuid/setgid bits set.")

        monitored_processes, monitor_failed = monitor_processes(monitor_time)
        logging.info(f"Monitored {len(monitored_processes)} unique processes.")

        if monitor_failed or not monitored_processes:
            logging.error("Monitoring failed or collected no processes. Aborting with no removals.")
            print("Monitoring failed or collected no processes. Aborting with no removals.")
            sys.exit(1)

        candidates = []
        for filepath, mode in setuid_setgid_files:
            if filepath in keep_paths or os.path.abspath(filepath) in keep_paths:
                logging.info(f"Keeping privileges for: {filepath} (listed in keep_paths).")
            elif check_privilege_usage(filepath, monitored_processes):
                logging.info(f"Keeping privileges for: {filepath} (seen running during the monitor window).")
            else:
                candidates.append(filepath)

        if apply_mode:
            print("Removal list:")
            for filepath in candidates:
                print(filepath)
        else:
            print("Dry run: candidates for privilege removal (nothing will be changed):")
            for filepath in candidates:
                print(filepath)

        if not apply_mode:
            for filepath in candidates:
                remove_privileges(filepath, dry_run=True)
            logging.info("Dry run complete. No privileges were removed.")
            return

        failed_paths = []
        for filepath in candidates:
            if not remove_privileges(filepath, dry_run=False):
                failed_paths.append(filepath)

        if failed_paths:
            for filepath in failed_paths:
                print(f"Failed to remove privileges from: {filepath}")
            print(f"Removal failures: {len(failed_paths)}")
            logging.error(f"Removal failures: {len(failed_paths)}")
            sys.exit(1)

    except SystemExit:
        raise
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()