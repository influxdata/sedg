#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

from cvelib.cve import (
    main_cve_add,
    main_cve_check_syntax,
)
from cvelib.gar import main_gar_dump_reports
from cvelib.github import main_dump_alerts
from cvelib.quay import main_quay_dump_reports
from cvelib.report import main_report

# for setuptools
cve_add = main_cve_add
cve_check_syntax = main_cve_check_syntax
cve_report = main_report
gar_dump_reports = main_gar_dump_reports
gh_dump_alerts = main_dump_alerts
quay_dump_reports = main_quay_dump_reports
