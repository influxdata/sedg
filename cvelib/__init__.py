#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

from cvelib.cve import (
    main_cve_add,
    main_cve_check_syntax,
)
from cvelib.gar import main_gar_report
from cvelib.report import (
    main_cve_report,
    main_cve_report_updated_bugs,
    main_gh_report,
)
from cvelib.quay import main_quay_report

# for setuptools
gar_report = main_gar_report
gh_report = main_gh_report
cve_add = main_cve_add
cve_check_syntax = main_cve_check_syntax
cve_report = main_cve_report
cve_report_updated_bugs = main_cve_report_updated_bugs
quay_report = main_quay_report
