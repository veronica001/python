#! /usr/bin/env python
# -*- coding: utf-8 -*-

from urllib import request

def gethtml(url):
    page = request.urlopen(url)
    html = page.read()
    return html

