import imp
import os
import sys

#Namecheap boilerplate code lol
#it's probably fine/functional

sys.path.insert(0, os.path.dirname(__file__))

wsgi = imp.load_source('wsgi', 'oidc.cgi')
application = wsgi.application
