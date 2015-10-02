#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from array import array

print (u'ê'.encode('utf8'))

exit()

a = u'tête'.encode('utf8').encode('string-escape')

b = json.dumps(a.encode('utf8'))

c = array('B', b.encode('utf8'))
print c
for i in c:
    print hex(i),
print
for i in c:
    print chr(i),

print json.loads(b).decode('string-escape')

