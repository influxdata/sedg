#!/usr/bin/env python3

from cvelib.common import CveException, rePatterns


# <product>[/<where or who>]_SOFTWARE[/<modifier>]: <status> [(<when>)]
#
# - <product> is the supporting technology (eg, 'git', 'snap', 'oci', etc)
# - <where or who> indicates where the software lives or in the case of snaps
#   or other technologies with a concept of publishers, who the publisher is
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
    def __init__(self, product, software, status, where="", modifier="", when=""):
        self.setProduct(product)
        self.setWhere(where)
        self.setSoftware(software)
        self.setModifier(modifier)
        self.setStatus(status)
        self.setWhen(when)

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
        if not rePatterns["pkg-product"].search(product):
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
