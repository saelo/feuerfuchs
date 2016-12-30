#!/usr/bin/env python3

import sys
import json
import hmac

SECRET = b"Saeyoozouy5hee6Vfeuerfuchs"
team_id = int(sys.argv[1])

token = hmac.new(SECRET, str(team_id).encode('ascii'), "sha1").hexdigest()
print(str(team_id) + ':' + token)

