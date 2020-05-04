#!/usr/bin/env python3
import os
import sys
import pymysql as MySQL
import urllib3,json,jwt,urllib.parse,base64
import traceback
from http import cookies

# Initialization

mysql_db,mysql_host=os.environ['cache_db'].split('@',1)
mysql_username,mysql_password=base64.b64decode(os.environ['cache_login']).decode().split(':',1)
con=MySQL.connect(mysql_host,mysql_username,mysql_password,mysql_db)

http=urllib3.PoolManager()

oa2_cids={d:i[0] for d,i in urllib.parse.parse_qs(os.environ['client_ids']).items()}
oa2_secs={d:s[0] for d,s in urllib.parse.parse_qs(os.environ['client_secrets']).items()}

defaultProvider=os.environ['client_ids'].split('=',1)[0]

redirect_uri=os.environ['redirect_uri']

errorURI='/'#TODO

#/Initialization

def _try(f,args=[],kwargs={}):
	try:
		return f(*args,**kwargs),None
	except Exception as E:
		return None,E

def _assert(b,m,e=AssertionError):
	if not b:
		raise e(m)
	return b

def _do(fak,errMsg):
	x,E=_try(*fak)
	_assert(not E,errMsg)
	return x

def application(environ, start_response):
	a="500 Internal Server Error"
	b=[('Content-Type', 'text/plain')]
	c=('THIS MESSAGE SHOULD NEVER APPEAR',)
	try:
		QS=_do((environ.get,('QUERY_STRING',)),
		  "No query string given.")
		
		qs=_do((urllib.parse.parse_qs,(QS,)),
		  "Invalid query string.")
		
		action=_do((qs.get,('action',)),
		  "No action given.")[0]
		
		_assert(action in ['login','callback'],
		  "Invalid action.")
		
		if action=='login':
			if 'email' in qs:
				hostname=_do((lambda em: (em[0].split('@',1)[1]),(qs['email'],)),
				  "Invalid email given.")
				provider=_do((getProviderByHostname,(hostname,)),
				  "Could not identify OpenID provider %s."%hostname)
			else:
				provider=defaultProvider
			
			config=_do((getProviderConfig,(provider,)),
			  "Unsupported OpenID provider.")
			_assert(provider in oa2_cids,
			  "Unsupported OpenID provider.")
			
			login_url=urllib.parse.urlunparse(
			 urllib.parse.urlparse(
			  config['authorization_endpoint']
			 )._replace(
			  query=urllib.parse.urlencode(
			   {
			    'client_id':     oa2_cids[provider],
			    'response_type': 'code',
			    'scope':         ' '.join((
			     'openid',
			     'email'         )),
			    'redirect_uri':  redirect_uri
			   },
			   doseq=True
			  )
			 )
			)
			a='202 Script Output Follows'
			b=[
			 ('Content-Type', 'text/html'),
			 ('Refresh', '%i; url=%s' % (0, login_url))
			]
			c=(
			 '<meta http-equiv="refresh" content="%i; url=%s" />' %
			  (0, login_url),
			 '<a href="%s">Click here if you are not redirected automatically</a>' %
			  (login_url,)
			)
		elif action=='callback':
			REFERER=_do((environ.get,('HTTP_REFERER',)),
			  "NO REFERER GIVEN.")
			_assert(REFERER,
			  "NO REFERER GIVEN.")
			
			referer=_do((urllib.parse.urlparse,(REFERER,)),
			  "INVALID REFERER.")
			provider=referer.hostname
			
			code=_do((qs.get,('code',)),
			  "NO AUTH CODE FOUND.")[0]
			
			tok=_do((code2tok,(provider,code,oa2_cids[provider],oa2_secs[provider],redirect_uri)),
			  "There was an error validating the code.")
			
			token=_do((parsetok,(tok,oa2_secs[provider]),{'audience':oa2_cids[provider]}),
			  "There was an error validating the token.")
			_assert(token['Verified'],
			  "There was an error validating the token.")
			
			token_cookie='id_token="%s"; Max-Age=%i' % (
			  urllib.parse.quote('|'.join(('%s:%s'%(k,v))
			   for k,v in [
				(token['Claims']['email'],
				 tok['id_token'])
			   ]
			  )),
			  tok['expires_in']&-64
			)
			
			a,b='200 Script output follows',[
			 ('Content-Type', 'application/json'),
			 ('Set-Cookie', token_cookie)
			]
			c=(json.dumps({'tok': tok, 'id_token': token},indent=2),)
	except AssertionError as e:
		a='400 Internal Server Error'
		b=[
		 ('Content-Type', 'text/plain'),
		# ('Refresh', '%i; url=%s' % (60, errorURL))
		]
		c='\n\n'.join(repr(arg) for arg in e.args)
	except:
		a='500 Internal Server Error'
		b=[
		 ('Content-Type', 'text/plain'),
		# ('Refresh', '%i; url=%s' % (60, errorURL))
		]
		c=('oh god',)
		c=traceback.format_exc()
	finally:
		start_response(a,b)
		return c

def getProviderByHostname(hostname,con=con):
	with con:
		cur=con.cursor()
		q='SELECT `provider` FROM `provideroverrides` WHERE `provideroverrides`.`hostname` = %s'
		cur.execute(q,hostname)
		for row in cur:
			if row is None:
				return hostname
			else:
				return row[0]

def getProviderConfig(provider,con=con):
	with con:
		cur=con.cursor()
		q='SELECT `json` FROM `configuration` WHERE `configuration`.`provider` = %s'
		cur.execute(q,provider)
		for row in cur:
			if row is not None:
				return json.loads(row[0])
			else:
				break
	configurl=urllib.parse.urlunparse(('https',provider,'/.well-known/openid-configuration','','',''))
	r=http.request('GET',configurl)
	return json.loads(r.data)

def getProviderKeys(provider,con=con):
	with con:
		cur=con.cursor()
		q='SELECT `jwk` from `certs` WHERE `certs`.`provider` = %s'
		keys={}
		cur.execute(q,provider)
		for jwk in cur:
			key=json.loads(jwk[0])
			keys[key['kid']]=key
	if not keys:
		configuration=getProviderConfig(provider)
		r=http.request('GET',keysurl)
		x=json.loads(r.data)['keys']
		for jwk in x:
			keys[key['kid']]=jwk
	return keys

def code2tok(provider,code,client_id,client_secret,redirect_uri=redirect_uri):
	endpoint=getProviderConfig(provider)['token_endpoint']
	r=http.request('POST',
	 endpoint,
	 {
		'code':          code,
		'client_id':     client_id,
		'client_secret': client_secret,
		'redirect_uri':  redirect_uri,
		'grant_type':    'authorization_code'
	 }
	)
	tok=json.loads(r.data)
	assert 'access_token' in tok or 'id_token' in tok,json.dumps(tok)
	return tok

def parseJwt(id_token,secret=None,audience=None,strict=False):
	t={
	 'Header':   jwt.get_unverified_header(id_token),
	 'Claims':   jwt.decode(id_token,verify=False),
	 'Verified': False
	}
	try:
		if t['Header']['alg']=='HS256':
			t['Claims']=jwt.decode(
				id_token,
				secret,
				verify=True,
				algorithms=['HS256'],
				#TODO: options
				audience=audience,
				issuer=t['Claims']['iss']
			)
			t['Verified']=True
		elif t['Header']['alg']=='RS256':
			provider=urllib.parse.urlparse(t['Claims']['iss']).hostname
			providerKeys=getProviderKeys(provider)
			pubJwt=providerKeys[t['Header']['kid']]
			pubkey=getattr(jwt.algorithms,
			 '%sAlgorithm' % pubJwt['kty']
			).from_jwk(json.dumps(pubJwt))
			jwt.decode(
				id_token,
				pubkey,
				verify=True,
				algorithms=['RS256'],
				#TODO: options
				audience=audience,
				issuer=t['Claims']['iss']
			)
			t['Verified']=True
	except:
		if strict:
			raise
	return t

def parsetok(x,secret=None,audience=None):
	token=parseJwt(x['id_token'],strict=False)
	if token['Verified']:
		return token
	if token['Header']['alg']=='HS256':
		token=parseJwt(x['id_token'],secret,audience=audience,strict=True)
	elif token['Header']['alg']=='RS256':
		token=parseJwt(x['id_token'],audience=audience,strict=True)
	assert token['Verified']
	return token

if __name__=='__main__':
	pass
#	raise NotImplementedError
