#!/usr/bin/env python3
#
# Copyright (c) 2021-2023 InfluxData
#
# Permission is hereby granted, free of charge, to any
# person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the
# Software without restriction, including without
# limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software
# is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice
# shall be included in all copies or substantial portions
# of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
# ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
# TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
# SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
# IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

from typing import Dict, List, Tuple

from cvelib.common import CveException, rePatterns, _patLengths, verifyDate


# <product>[/<where or who>]_SOFTWARE[/<modifier>]: <status> [(<when>)]
#
# - <product> is the supporting technology (eg, 'git', 'snap', 'oci', etc).
#   Could also be distribution (eg, 'ubuntu', 'debian', suse', etc).
# - <where or who> indicates where the software lives or in the case of snaps
#   or other technologies with a concept of publishers, who the publisher is.
#   For distributions (eg, 'ubuntu', 'debian', 'suse', etc), where indicates
#   the release of the distribution (eg, 'ubuntu/focal' indicates 20.04 for
#   Ubuntu).
# - SOFTWARE is the name of the software as dictated by the product (eg, the
#   deb source package, the name of the snap or the name of the software
#   project)
# - <modifier> is an optional key for grouping collections of packages (eg,
#   'melodic' for the ROS Melodic release or 'rocky' for the OpenStack Rocky
#   release)
# - <status> indicates the statuses (eg, needs-triage, needed, pending,
#   released, etc)
# - <when> indicates 'when' the software will be/was fixed when used with the
#   'pending' or 'released' status (eg, the source package version, snap #
#   revision, etc)
class CvePkg(object):
    def __init__(
        self,
        product: str,
        software: str,
        status: str,
        where: str = "",
        modifier: str = "",
        when: str = "",
        compatUbuntu: bool = False,
    ) -> None:
        self.product: str = ""
        self.software: str = ""
        self.status: str = ""
        self.where: str = ""
        self.modifer: str = ""
        self.when: str = ""
        self.compatUbuntu: bool = compatUbuntu
        self.patches: List[str] = []
        self.tags: Dict[str, List[str]] = {}
        self.priorities: Dict[str, str] = {}
        self.closeDates: Dict[str, str] = {}

        self.setProduct(product)
        self.setWhere(where)
        self.setSoftware(software)
        self.setModifier(modifier)
        self.setStatus(status)
        self.setWhen(when)

    def __str__(self) -> str:
        s: str = self.what()
        s += ": %s" % self.status
        if self.when:
            s += " (%s)" % (self.when)

        return s

    def __repr__(self) -> str:
        return self.__str__()

    def what(self) -> str:
        """The product/where_software/modifier"""
        s: str = ""
        if self.product:
            s += self.product
            if self.where:
                s += "/"
                s += self.where
            s += "_"
        s += self.software
        if self.modifier:
            s += "/%s" % self.modifier
        return s

    def setProduct(self, product: str) -> None:
        """Set product"""
        if self.compatUbuntu:
            if not rePatterns["pkg-product-ubuntu"].search(product):
                raise CveException("invalid product '%s'" % product)
        elif not rePatterns["pkg-product"].search(product):
            raise CveException("invalid product '%s'" % product)
        self.product = product

    def setWhere(self, where: str) -> None:
        """Set where"""
        if where == "":
            self.where = ""
            return
        # honor the common length but reuse the software regex for 'where'
        if len(where) > _patLengths["pkg-where"]:
            raise CveException("invalid where '%s'" % where)
        elif self.compatUbuntu:
            if not rePatterns["pkg-software-ubuntu"].search(where):
                raise CveException("invalid compat where '%s'" % where)
        elif not rePatterns["pkg-software"].search(where):
            raise CveException("invalid where '%s'" % where)
        self.where = where

    def setSoftware(self, software: str) -> None:
        """Set software"""
        if self.compatUbuntu:
            if not rePatterns["pkg-software-ubuntu"].search(software):
                raise CveException("invalid compat software '%s'" % software)
        elif not rePatterns["pkg-software"].search(software):
            raise CveException("invalid software '%s'" % software)
        self.software = software

    def setModifier(self, modifier: str) -> None:
        """Set modifier"""
        if modifier == "":
            self.modifier = ""
            return
        # honor the common length but reuse the software regex for 'where'
        if len(modifier) > _patLengths["pkg-modifier"]:
            raise CveException("invalid modifier '%s'" % modifier)
        if self.compatUbuntu:
            if not rePatterns["pkg-software-ubuntu"].search(modifier):
                raise CveException("invalid compat modifier '%s'" % modifier)
        elif not rePatterns["pkg-software"].search(modifier):
            raise CveException("invalid modifier '%s'" % modifier)
        self.modifier = modifier

    def setStatus(self, status: str) -> None:
        """Set status"""
        if not rePatterns["pkg-status"].search(status):
            raise CveException("invalid status '%s'" % status)
        self.status = status

    def setWhen(self, when: str) -> None:
        """Set when"""
        if when == "":
            self.when = ""
            return
        if not rePatterns["pkg-when"].search(when):
            raise CveException("invalid when '%s'" % when)
        self.when = when

    def setPatches(self, patches: List[str], compatUbuntu: bool) -> None:
        """Set patches"""
        self.patches = []
        for patch in patches:
            patch = patch.strip()
            if compatUbuntu:
                if not rePatterns["pkg-patch-ubuntu"].search(patch):
                    raise CveException("invalid patch for compat '%s'" % patch)
            elif not rePatterns["pkg-patch"].search(patch):
                raise CveException("invalid patch '%s'" % patch)
            self.patches.append(patch)

    def setTags(self, tagList: List[Tuple[str, str]]) -> None:
        """Set tag"""
        self.tags = {}
        for tagKey, tagVal in tagList:
            self.tags[tagKey] = []
            for t in tagVal.split():
                t = t.strip()
                if not rePatterns["pkg-tags"].search(t):
                    raise CveException("invalid tag '%s'" % t)
                self.tags[tagKey].append(t)

    def setPriorities(self, priorityList: List[Tuple[str, str]]) -> None:
        """Set package priorities"""
        self.priorites = {}
        for priKey, priVal in priorityList:
            # NOTE: we don't special-case 'untriaged' because that makes no sense
            # with package priority (ie, if you don't know, you should not set it)
            if priVal == "untriaged":
                raise CveException(
                    "invalid package priority '%s' (please remove or set)" % priVal
                )

            if not rePatterns["priorities"].search(priVal):
                raise CveException("invalid package priority '%s'" % priVal)

            self.priorities[priKey] = priVal

    def setCloseDates(self, closeDatesList: List[Tuple[str, str]]) -> None:
        """Set closeDates"""
        self.closeDates = {}
        for closeDateKey, closeDateVal in closeDatesList:
            verifyDate(closeDateKey, closeDateVal)
            self.closeDates[closeDateKey] = closeDateVal


def parse(s: str, compatUbuntu: bool = False) -> CvePkg:
    """Parse a string and return a CvePkg"""
    if "\n" in s:
        raise CveException("invalid package entry '%s' (expected single line)" % s)
    if compatUbuntu:
        if not rePatterns["pkg-full-ubuntu"].search(s):
            raise CveException("invalid package entry for compat '%s'" % s)
    elif not rePatterns["pkg-full"].search(s):
        raise CveException("invalid package entry '%s'" % s)

    product: str = ""
    software: str = ""
    status: str = ""
    where: str = ""
    modifier: str = ""
    when: str = ""

    # when may have ':', so only split on the first one
    (product_software, status_when) = s.split(":", 1)

    # Ubuntu disallows "_" in <software>, but otherwise we allow it
    product_where, software_mod = product_software.split("_", maxsplit=1)

    if "/" in product_where:
        product, where = product_where.split("/")
    else:
        product = product_where

    # compatUbuntu allows foo_bar/baz, otherwise allow foo/bar/baz
    if "/" in software_mod:
        software, modifier = software_mod.split("/")
    else:
        software = software_mod

    status = status_when.strip().split()[0]
    if "(" in status_when:
        when = status_when.split("(", 1)[1].rstrip(")").strip()

    return CvePkg(
        product,
        software,
        status,
        where=where,
        modifier=modifier,
        when=when,
        compatUbuntu=compatUbuntu,
    )


def cmp_pkgs(a: CvePkg, b: CvePkg) -> int:
    """cmp_pkgs() takes 'a' and 'b' and compares by software, then product,
    then where. When comparing product, put build artifacts after others and
    put 'upstream' before others.
    """
    if a.software < b.software:
        return -1
    elif a.software > b.software:
        return 1
    # a.software == b.software
    # put build artifacts after others
    elif not rePatterns["pkg-product-build-artifact"].search(a.product) and rePatterns[
        "pkg-product-build-artifact"
    ].search(b.product):
        return -1
    elif rePatterns["pkg-product-build-artifact"].search(a.product) and not rePatterns[
        "pkg-product-build-artifact"
    ].search(b.product):
        return 1
    # put upstream before others
    elif a.product == "upstream" and b.product != "upstream":
        return -1
    elif a.product != "upstream" and b.product == "upstream":
        return 1
    elif a.product < b.product:
        return -1
    elif a.product > b.product:
        return 1
    # a.software == b.software && a.product == b.product
    elif a.where < b.where:
        return -1
    elif a.where > b.where:
        return 1

    return 0
