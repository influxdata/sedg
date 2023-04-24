from setuptools import setup
if __name__ == "__main__":
    # TODO: console_scripts for python scripts
    setup(
        scripts=[
            # bash
            "bin/cve-edit",
            "bin/cve-nfu",
            # python
            "bin/cve-add",
            "bin/cve-check-syntax",
            "bin/cve-report",
            "bin/cve-report-updated-bugs",
            "bin/gar-report",
            "bin/gh-report",
            "bin/quay-report",
        ])
