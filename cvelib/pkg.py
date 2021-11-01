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
        self.tags = {}
        self.priorities = {}

    def __str__(self):
        s = self.what()
        s += ": %s" % self.status
        if self.when:
            s += " (%s)" % (self.when)

        return s

    def __repr__(self):
        return self.__str__()

    def what(self):
        """The product/where_software/modififer"""
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
        return s

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
        if self.compatUbuntu:
            if not rePatterns["pkg-software-ubuntu"].search(where):
                raise CveException("invalid where '%s'" % where)
        elif not rePatterns["pkg-software"].search(where):
            raise CveException("invalid where '%s'" % where)
        self.where = where

    def setSoftware(self, software):
        """Set software"""
        if self.compatUbuntu:
            if not rePatterns["pkg-software-ubuntu"].search(software):
                raise CveException("invalid Ubuntu software '%s'" % software)
        elif not rePatterns["pkg-software"].search(software):
            raise CveException("invalid software '%s'" % software)
        self.software = software

    def setModifier(self, modifier):
        """Set modifier"""
        if modifier == "":
            self.modifier = ""
            return
        if self.compatUbuntu:
            if not rePatterns["pkg-software-ubuntu"].search(modifier):
                raise CveException("invalid Ubuntu modifier '%s'" % modifier)
        elif not rePatterns["pkg-software"].search(modifier):
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

    def setPatches(self, patches, compatUbuntu):
        """Set patches"""
        if not isinstance(patches, list):
            raise CveException("invalid patches (not a list)")

        self.patches = []
        for patch in patches:
            if not isinstance(patch, str):
                raise CveException("invalid patch (not a string)")
            patch = patch.strip()
            if compatUbuntu:
                if not rePatterns["pkg-patch-ubuntu"].search(patch):
                    raise CveException("invalid patch for Ubuntu '%s'" % patch)
            elif not rePatterns["pkg-patch"].search(patch):
                raise CveException("invalid patch '%s'" % patch)
            self.patches.append(patch)

    def setTags(self, tagList):
        """Set tag"""
        if not isinstance(tagList, list):
            raise CveException("invalid tags (not a list)")

        self.tags = {}
        for tagKey, tagVal in tagList:
            self.tags[tagKey] = []
            for t in tagVal.split():
                t = t.strip()
                if not rePatterns["pkg-tags"].search(t):
                    raise CveException("invalid tag '%s'" % t)
                self.tags[tagKey].append(t)

    def setPriorities(self, priorityList):
        """Set package priorities"""
        if not isinstance(priorityList, list):
            raise CveException("invalid priorities (not a list)")

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


def parse(s, compatUbuntu=False):
    """Parse a string and return a CvePkg"""
    if not isinstance(s, str):
        raise CveException("invalid package entry (not a string)")
    if "\n" in s:
        raise CveException("invalid package entry '%s' (expected single line)" % s)
    if compatUbuntu:
        if not rePatterns["pkg-full-ubuntu"].search(s):
            raise CveException("invalid package entry for Ubuntu '%s'" % s)
    elif not rePatterns["pkg-full"].search(s):
        raise CveException("invalid package entry '%s'" % s)

    product = ""
    software = ""
    status = ""
    where = ""
    modifier = ""
    when = ""

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
