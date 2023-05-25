#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

from cvelib.cve import (
    main_cve_add,
    main_cve_check_syntax,
)
from cvelib.github import main_dump_alerts
from cvelib.report import main_report

# for setuptools
cve_add = main_cve_add
cve_check_syntax = main_cve_check_syntax
cve_report = main_report
gh_dump_alerts = main_dump_alerts
