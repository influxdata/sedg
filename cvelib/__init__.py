#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

from cvelib.cve import (
    main_cve_add,
    main_cve_check_syntax,
)
from cvelib.dso import main_dso_dump_reports
from cvelib.gar import main_gar_dump_reports
from cvelib.github import main_dump_alerts
from cvelib.quay import main_quay_dump_reports
from cvelib.report import main_report
from cvelib.sql import main_cve_query
from cvelib.wizard import main_cve_add_wizard

# for setuptools
cve_add = main_cve_add
cve_add_wizard = main_cve_add_wizard
cve_check_syntax = main_cve_check_syntax
cve_query = main_cve_query
cve_report = main_report
dso_dump_reports = main_dso_dump_reports
gar_dump_reports = main_gar_dump_reports
gh_dump_alerts = main_dump_alerts
quay_dump_reports = main_quay_dump_reports
