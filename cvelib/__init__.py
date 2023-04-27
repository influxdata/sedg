#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT

from cvelib.cve import (
    main_cve_add,
    main_cve_check_syntax,
)
from cvelib.gar import main_gar_report
from cvelib.report import main_report
from cvelib.quay import main_quay_report

# for setuptools
gar_report = main_gar_report
cve_add = main_cve_add
cve_check_syntax = main_cve_check_syntax
cve_report = main_report
quay_report = main_quay_report
