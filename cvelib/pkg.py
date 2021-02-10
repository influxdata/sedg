#!/usr/bin/env python3

from cvelib.common import CveException, rePatterns


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
        product,
        software,
        status,
        where="",
        modifier="",
        when="",
        compatUbuntu=False,
    ):
        self.compatUbuntu = compatUbuntu
        self.setProduct(product)
        self.setWhere(where)
        self.setSoftware(software)
        self.setModifier(modifier)
        self.setStatus(status)
        self.setWhen(when)
        self.patches = []

    def __str__(self):
        s = ""
        if self.product:
            s += self.product
            if self.where:
                s += "/"
                s += self.where
            s += "_"
        s += self.software
        if self.modifier:
            s += "/%s" % self.modifier
        s += ": %s" % self.status
        if self.when:
            s += " (%s)" % (self.when)

        return s

    def __repr__(self):
        return self.__str__()

    def setProduct(self, product):
        """Set product"""
        if self.compatUbuntu:
            if not rePatterns["pkg-product-ubuntu"].search(product):
                raise CveException("invalid product '%s'" % product)
        elif not rePatterns["pkg-product"].search(product):
            raise CveException("invalid product '%s'" % product)
        self.product = product

    def setWhere(self, where):
        """Set where"""
        if where == "":
            self.where = ""
            return
        if not rePatterns["pkg-software"].search(where):
            raise CveException("invalid where '%s'" % where)
        self.where = where

    def setSoftware(self, software):
        """Set software"""
        if not rePatterns["pkg-software"].search(software):
            raise CveException("invalid software '%s'" % software)
        self.software = software

    def setModifier(self, modifier):
        """Set modifier"""
        if modifier == "":
            self.modifier = ""
            return
        if not rePatterns["pkg-software"].search(modifier):
            raise CveException("invalid modifier '%s'" % modifier)
        self.modifier = modifier

    def setStatus(self, status):
        """Set status"""
        if not rePatterns["pkg-status"].search(status):
            raise CveException("invalid status '%s'" % status)
        self.status = status

    def setWhen(self, when):
        """Set when"""
        if when == "":
            self.when = ""
            return
        if not rePatterns["pkg-when"].search(when):
            raise CveException("invalid when '%s'" % when)
        self.when = when

    def setPatches(self, patches):
        """Set patches"""
        if not isinstance(patches, list):
            raise CveException("invalid patches (not a list)")

        self.patches = []
        for patch in patches:
            if not isinstance(patch, str):
                raise CveException("invalid patch (not a string)")
            patch = patch.strip()
            if not rePatterns["pkg-patch"].search(patch):
                raise CveException("invalid patch '%s'" % patch)
            self.patches.append(patch)


def parse(s, compatUbuntu=False):
    """Parse a string and return a CvePkg"""
    if not isinstance(s, str):
        raise CveException("invalid package entry (not a string)")
    if compatUbuntu:
        if not rePatterns["pkg-full-ubuntu"].search(s):
            raise CveException("invalid package entry '%s'" % s)
    elif not rePatterns["pkg-full"].search(s):
        raise CveException("invalid package entry '%s'" % s)

    product = ""
    software = ""
    status = ""
    where = ""
    modifier = ""
    when = ""

    (product_software, status_when) = s.split(":")

    product_where, software_mod = product_software.split("_")
    if "/" in product_where:
        product, where = product_where.split("/")
    else:
        product = product_where

    if "/" in software_mod:
        software, modifier = software_mod.split("/")
    else:
        software = software_mod

    status = status_when.strip().split()[0]
    if "(" in status_when:
        when = status_when.split("(")[0].rstrip(")").strip()

    return CvePkg(
        product,
        software,
        status,
        where=where,
        modifier=modifier,
        when=when,
        compatUbuntu=compatUbuntu,
    )
