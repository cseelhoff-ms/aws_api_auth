import requests
import hashlib
import hmac
from datetime import datetime

access_id = 'ENTER ACCESS ID HERE'
secret_key = 'ENTER SECRET KEY HERE'
region = 'us-east-2'
service = 's3'
endpoint = 'https://securenetops.s3.amazonaws.com/?publicAccessBlock'
host = 'securenetops.s3.amazonaws.com'
path = '/'
qs = 'publicAccessBlock='
req_method = 'PUT'
requestBody = """<PublicAccessBlockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <BlockPublicAcls>False</BlockPublicAcls>
   <IgnorePublicAcls>False</IgnorePublicAcls>
   <BlockPublicPolicy>False</BlockPublicPolicy>
   <RestrictPublicBuckets>False</RestrictPublicBuckets>
</PublicAccessBlockConfiguration>"""

requestBodyEncoded = requestBody.encode('utf-8')
content_hash = hashlib.sha256(requestBodyEncoded)
x_amz_content_sha256 = content_hash.hexdigest()
dateYYYYMMDD = datetime.utcnow().strftime('%Y%m%d')
x_amz_date = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
cano_headers = set({
    'content-type:application/xml;charset=utf-8',
    'host:' + host,
    'x-amz-content-sha256:' + x_amz_content_sha256,
    'x-amz-date:' + x_amz_date
})
cano_headers = 'content-type:application/xml;charset=utf-8\n' + 'host:' + host + '\nx-amz-content-sha256:' + x_amz_content_sha256 + '\nx-amz-date:' + x_amz_date + '\n'
signed_headers = 'content-type;host;x-amz-content-sha256;x-amz-date'
req_parts = [req_method, path, qs, cano_headers, signed_headers, x_amz_content_sha256]
cano_req = '\n'.join(req_parts)
cano_req_hsh = hashlib.sha256(cano_req.encode())

signing_key_scope = dateYYYYMMDD + '/' + region + '/' + service + '/' 'aws4_request'
sig_items = ['AWS4-HMAC-SHA256', x_amz_date, signing_key_scope, cano_req_hsh.hexdigest()]
sig_string = '\n'.join(sig_items)
sig_string = sig_string.encode('utf-8')

init_key = ('AWS4' + secret_key).encode('utf-8')
date_key = hmac.new(init_key, dateYYYYMMDD.encode('utf-8'), hashlib.sha256).digest()
region_key = hmac.new(date_key, region.encode('utf-8'), hashlib.sha256).digest()
service_key = hmac.new(region_key, service.encode('utf-8'), hashlib.sha256).digest()
signingkey_key = hmac.new(service_key, 'aws4_request'.encode('utf-8'), hashlib.sha256).digest()
sig = hmac.new(signingkey_key, sig_string, hashlib.sha256).hexdigest()

auth_str = 'AWS4-HMAC-SHA256 '
auth_str += 'Credential={}/{}, '.format(access_id, signing_key_scope)
auth_str += 'SignedHeaders={}, '.format(signed_headers)
auth_str += 'Signature={}'.format(sig)

headers = {
    'content-type': 'application/xml;charset=utf-8',
    'x-amz-date': x_amz_date,
    'x-amz-content-sha256': x_amz_content_sha256,
    'Authorization': auth_str
}

response = requests.put(endpoint, headers=headers, data=requestBodyEncoded)
print(response)
