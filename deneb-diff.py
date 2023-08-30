import os
import subprocess
from tabulate import tabulate  # You'll need to install this with pip.

DIR = "./"
BASE_BRANCH = "unstable"
FEATURE_BRANCH = "deneb-free-blobs"
IGNORE_LIST = [
    ".mypy_cache",
    ".vscode",
    ".git",
    ".cargo",
    ".idea",
    "target",
]


def get_stats(dir, table):
    for filename in os.listdir(dir):
        path = os.path.join(dir, filename)
        if os.path.isdir(path):
            if filename in IGNORE_LIST:
                continue
            elif path == os.path.join(dir, "beacon_node"):
                get_stats(path, table)
            else:
                result = subprocess.run(
                    ["git", "diff", "--shortstat", FEATURE_BRANCH, BASE_BRANCH, path],
                    stdout=subprocess.PIPE,
                )
                formatted = result.stdout.decode("utf-8").strip("\n")
                row = [path]
                row += formatted.split(", ")
                row += ["Unassigned"]
                table.append(row)
    return table


table = get_stats("./", [])
print(tabulate(table, headers=["Component", "", "", "", "Reviewer"]))
