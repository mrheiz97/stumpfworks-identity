"""TEST ONLY: privileged local journal inspection, NOT an authenticated receipt API."""
import json
import os
import re
import sys

import tdb
from broker_candidate import fixture

fixture()
if len(sys.argv)!=2 or not re.fullmatch(r"[0-9a-f]{32}",sys.argv[1]):
    raise RuntimeError("invalid laboratory operation ID")
operation=bytes.fromhex(sys.argv[1])
journal=tdb.Tdb("/tmp/native-cas/journal.tdb",0,tdb.DEFAULT,os.O_RDONLY)
try:
    record=journal.get(b"O"+operation)
    version=journal.get(b"V"+operation)
    if record is None:
        result={"state":0,"digest":"","version":""}
    elif len(record)!=33 or record[-1] not in (1,2,3):
        raise RuntimeError("invalid laboratory receipt")
    else:
        if record[-1]==2 and (version is None or len(version)!=8):
            raise RuntimeError("missing committed version")
        result={"state":record[-1],"digest":record[:32].hex(),
                "version":str(int.from_bytes(version,"big")) if record[-1]==2 else ""}
    print(json.dumps(result))
finally:
    journal.close()
