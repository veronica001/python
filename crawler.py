#! /usr/bin/env python
# -*- coding: utf-8 -*-

from urllib import request
import re

def gethtml(url):
    page = request.urlopen(url)
    html = page.read()
    return html

