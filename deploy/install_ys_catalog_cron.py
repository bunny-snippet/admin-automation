"""Install only the managed catalog block; preserve and privately back up user cron."""
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess

BEGIN = "# BEGIN managed-warrior-ys-catalog-sync"
END = "# END managed-warrior-ys-catalog-sync"


def replace_managed_block(current, fragment):
    desired_lines = fragment.splitlines(keepends=True)
    begin = [i for i, line in enumerate(desired_lines) if line.strip() == BEGIN]
    end = [i for i, line in enumerate(desired_lines) if line.strip() == END]
    if len(begin) != 1 or len(end) != 1 or begin[0] >= end[0]:
        raise ValueError("Managed cron asset is invalid.")
    block = "".join(desired_lines[begin[0]:end[0] + 1]).rstrip("\n") + "\n"
    lines = current.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.strip() == BEGIN]
    ends = [i for i, line in enumerate(lines) if line.strip() == END]
    if not starts and not ends:
        return current + ("\n" if current and not current.endswith("\n") else "") + block
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise ValueError("Ambiguous existing managed cron markers; nothing changed.")
    return "".join(lines[:starts[0]]) + block + "".join(lines[ends[0] + 1:])


def read_crontab():
    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True,
                            env={**os.environ, "LC_ALL": "C"}, check=False)
    if result.returncode == 0:
        return result.stdout
    if result.returncode == 1 and "no crontab for" in result.stderr.lower():
        return ""
    raise RuntimeError("Could not read current user crontab; nothing changed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install", action="store_true", help="Back up then install only the managed catalog block; default is read-only check.")
    options = parser.parse_args()
    # Intended user is explicit; never accidentally replace root's crontab.
    import pwd
    if pwd.getpwuid(os.geteuid()).pw_name != "bunny":
        raise RuntimeError("Run as the existing Warrior user bunny; nothing changed.")
    repo = Path(__file__).resolve().parent.parent
    current = read_crontab()
    fragment = (repo / "deploy" / "warrior-ys-catalog-sync.cron").read_text()
    desired = replace_managed_block(current, fragment)
    if current == desired:
        print("Managed catalog cron is already installed; no changes.")
        return
    if not options.install:
        print("Managed catalog cron needs installation; read-only check made no changes.")
        return
    backup_dir = repo / "tmp"
    backup_dir.mkdir(mode=0o700, exist_ok=True)
    log_fd = os.open(str(backup_dir / "ys-catalog-sync.log"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.close(log_fd)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = backup_dir / ("ys-catalog-crontab-before-" + stamp + ".txt")
    fd = os.open(str(backup), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
        handle.write(current)
    if read_crontab() != current:
        raise RuntimeError("Crontab changed during preparation; backup saved but nothing installed.")
    result = subprocess.run(["crontab", "-"], input=desired, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError("Crontab installation failed; private backup retained.")
    if read_crontab() != desired:
        raise RuntimeError("Crontab verification differed; inspect manually using the private backup.")
    print("Managed catalog cron installed and verified; unrelated entries preserved.")
    print("Private previous-crontab backup: " + str(backup))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError):
        # Do not echo process errors or existing crontab contents (may contain keys).
        raise SystemExit("Catalog cron operation failed safely; inspect the private backup and user permissions.")
