"""NON-DEPLOYABLE laboratory mechanism probe; no listener, daemon or Identity adapter.

Local sam.ldb access requires DC filesystem authority. A normal AD token limits
the demonstrated operations, NOT a compromised process with that filesystem access.
"""
import hashlib
import json
import os
import re
import sqlite3

import ldb
from samba import auth
from samba.credentials import Credentials, DONT_USE_KERBEROS
from samba.dcerpc import security
from samba.ndr import ndr_unpack
from samba.param import LoadParm
from samba.samdb import SamDB

DB = "/tmp/profile-domain/private/sam.ldb"
FIELDS = ("displayName", "givenName", "sn", "mail")
FLAGS = auth.AUTH_SESSION_INFO_DEFAULT_GROUPS | auth.AUTH_SESSION_INFO_AUTHENTICATED | auth.AUTH_SESSION_INFO_SIMPLE_PRIVILEGES


class Denied(Exception):
    pass


class Conflict(Denied):
    pass


def fixture():
    if os.environ.get("IDENTITY_AD_PROFILE_LAB") != "/tmp/lab-config.json" or set(os.listdir("/sys/class/net")) != {"lo"}:
        raise Denied("networkless laboratory required")
    with open("/tmp/lab-config.json", encoding="utf-8") as f:
        data = json.load(f)
    if data["Config"]["URL"] != "ldaps://dc1.profile.test:636" or data["Config"]["BaseDN"] != "DC=profile,DC=test":
        raise Denied("synthetic domain required")
    return data


def loadparm():
    lp = LoadParm(); lp.load("/tmp/profile-domain/etc/smb.conf")
    lp.set("tls verify peer", "ca_and_name")
    return lp


def one(db, base, expression="(objectClass=*)", attrs=None, scope=ldb.SCOPE_BASE):
    rows = db.search(base=base, expression=expression, scope=scope, attrs=attrs)
    if len(rows) != 1:
        raise Denied("ambiguous or missing object")
    return rows[0]


def sid(row):
    return str(ndr_unpack(security.dom_sid, row["objectSid"][0]))


def text(row, key, default=""):
    values = row.get(key)
    if not values:
        return default
    return values[0].decode() if isinstance(values[0], bytes) else str(values[0])


def modify(db, dn, values):
    msg = ldb.Message(); msg.dn = ldb.Dn(db, str(dn))
    for key, value in values.items():
        msg[key] = ldb.MessageElement(value, ldb.FLAG_MOD_REPLACE, key)
    db.modify(msg)


def journal_path():
    case = os.environ.get("IDENTITY_BROKER_CASE", "")
    if not re.fullmatch(r"[0-9a-f]{32}", case):
        raise Denied("isolated test case required")
    return "/tmp/profile-broker-research/" + case + "/journal.db"


def journal_open():
    db = sqlite3.connect(journal_path(), timeout=3)
    db.execute("PRAGMA synchronous=FULL")
    return db


def initialize_journal():
    os.umask(0o077); os.makedirs(os.path.dirname(journal_path()), mode=0o700)
    with journal_open() as db:
        db.executescript("CREATE TABLE operations(id TEXT PRIMARY KEY,digest TEXT,state TEXT,target TEXT); CREATE UNIQUE INDEX one_uncertain_target ON operations(target) WHERE state='applying'; CREATE TABLE audit(id TEXT,event TEXT,actor TEXT,target TEXT,attributes TEXT);")


def record(request, actor, state, initial=False):
    # No password, profile values, raw LDAP errors or DN in the audit table.
    digest = hashlib.sha256(json.dumps([actor, request], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    with journal_open() as db:
        db.execute("BEGIN IMMEDIATE")
        if initial:
            previous = db.execute("SELECT digest,state FROM operations WHERE id=?", (request["id"],)).fetchone()
            if previous:
                if previous[0] != digest:
                    raise Denied("idempotency conflict")
                return previous[1]
            if db.execute("SELECT 1 FROM operations WHERE target=? AND state='applying'", (request["target"],)).fetchone():
                raise Denied("target has an uncertain operation")
            db.execute("INSERT INTO operations VALUES(?,?,'applying',?)", (request["id"], digest, request["target"]))
        else:
            changed = db.execute("UPDATE operations SET state=? WHERE id=? AND digest=? AND state='applying'", (state, request["id"], digest)).rowcount
            if changed != 1:
                raise Denied("invalid journal transition")
        db.execute("INSERT INTO audit VALUES(?,?,?,?,?)", (request["id"], state, actor, request["target"], json.dumps(sorted(request["changes"]))))
    return None


class Candidate:
    def __init__(self):
        self.fixture = fixture(); self.config = self.fixture["Config"]; self.lp = loadparm()
        # Bootstrap solely constructs the fixed normal writer token. No client
        # can supply a session, SYSTEM flag, credential selector or DB path.
        root = SamDB(url=DB, lp=self.lp, session_info=auth.system_session(self.lp))
        writer = one(root, self.config["WriterDN"], attrs=["objectSid","objectGUID","userAccountControl"])
        self.writer_sid = sid(writer)
        self.check_writer(writer)
        session = auth.user_session(root, lp_ctx=self.lp, dn=self.config["WriterDN"], session_info_flags=FLAGS)
        self.check_token(session)
        self.db = SamDB(url=DB, lp=self.lp, session_info=session)

    def check_writer(self,row):
        if sid(row)!=self.fixture["BrokerWriterSID"] or bytes(row["objectGUID"][0]).hex()!=self.fixture["BrokerWriterGUID"] or text(row,"userAccountControl")!="512":
            raise Denied("writer disabled or identity changed")

    def check_token(self, session):
        token = session.security_token
        if token.is_system() or str(token.sids[0]) != self.writer_sid:
            raise Denied("nondelegated token")
        if any(token.has_privilege(p) for p in (security.SEC_PRIV_RESTORE, security.SEC_PRIV_SECURITY, security.SEC_PRIV_TAKE_OWNERSHIP)):
            raise Denied("privileged token")
        forbidden = {self.config["DomainSID"] + "-" + rid for rid in ("500", "512", "518", "519")}
        if forbidden.intersection(map(str, token.sids)) or "S-1-5-32-544" in map(str, token.sids):
            raise Denied("administrative group token")

    def authenticate(self, username, password):
        if not isinstance(username,str) or not re.fullmatch(r"[a-zA-Z0-9._-]{1,64}", username) or not isinstance(password,str) or not password or len(password) > 1024:
            raise Denied("invalid authentication")
        row = one(self.db, self.config["BaseDN"], "(&(objectClass=user)(sAMAccountName=" + ldb.binary_encode(username) + "))", ["objectSid"], ldb.SCOPE_SUBTREE)
        credentials = Credentials(); credentials.guess(self.lp); credentials.set_bind_dn(str(row.dn)); credentials.set_password(password); credentials.set_kerberos_state(DONT_USE_KERBEROS)
        remote = SamDB(url="ldaps://dc1.profile.test:636", lp=self.lp, credentials=credentials)
        authenticated = one(remote, str(row.dn), attrs=["objectSid"])
        if sid(authenticated) != sid(row):
            raise Denied("authentication identity changed")
        return sid(row)

    def snapshot(self):
        row = one(self.db, self.config["ManagedOU"], "(sAMAccountName=casprobe)", None, ldb.SCOPE_ONELEVEL)
        return {"target": bytes(row["objectGUID"][0]).hex(), "sid": sid(row), "version": text(row,"uSNChanged"),
                "domain": self.config["DomainGUID"], "dc": self.config["DCIdentity"]}

    def execute(self, request, username, password, fault=None, hold=None):
        if not isinstance(request,dict) or set(request) != {"id", "target", "sid", "version", "domain", "dc", "changes"} or not isinstance(request["id"],str) or not re.fullmatch(r"[0-9a-f]{32}", request["id"]):
            raise Denied("untyped request")
        if request["domain"]!=self.config["DomainGUID"] or request["dc"]!=self.config["DCIdentity"] or not isinstance(request["version"],str) or not request["version"].isdigit() or len(request["version"])>20:
            raise Denied("invalid identity/version binding")
        changes = request["changes"]
        if not isinstance(changes,dict) or not changes or set(changes) - set(FIELDS):
            raise Denied("attribute not allowed")
        for key, values in changes.items():
            limit = {"displayName": 256, "givenName": 64, "sn": 64, "mail": 254}[key]
            if not isinstance(values, list) or len(values) > 1 or any(not isinstance(v, str) or not v or len(v.encode()) > limit or any(ord(c) < 32 for c in v) for v in values):
                raise Denied("invalid value")
        actor = self.authenticate(username, password)  # never perform network auth under the DSDB write lock
        previous = record(request, actor, "applying", initial=True)
        if previous is not None:
            return previous  # including uncertain applying: never execute a claim twice
        self.db.transaction_start()
        try:
            # Refresh the normal token and current authorization within this same
            # local DSDB transaction, then retain that subject for every write.
            writer=one(self.db,self.config["WriterDN"],attrs=["objectGUID","objectSid","userAccountControl"])
            self.check_writer(writer)
            session = auth.user_session(self.db, lp_ctx=self.lp, dn=self.config["WriterDN"], session_info_flags=FLAGS)
            self.check_token(session); self.db.set_session_info(session)
            actor_row = one(self.db, self.config["BaseDN"], "(objectSid=" + actor + ")", ["userAccountControl"], ldb.SCOPE_SUBTREE)
            group = one(self.db, self.config["OperatorGroupDN"], attrs=["objectGUID", "member"])
            if text(actor_row,"userAccountControl") != "512" or bytes(group["objectGUID"][0]).hex() != self.config["OperatorGroupGUID"] or not any(ldb.Dn(self.db, v.decode()) == actor_row.dn for v in group.get("member", [])):
                raise Denied("current role denied")
            domain = one(self.db, self.config["BaseDN"], attrs=["objectGUID", "objectSid"])
            root = one(self.db, "", attrs=["dsServiceName"])
            dc = one(self.db, text(root,"dsServiceName"), attrs=["invocationId"])
            if bytes(domain["objectGUID"][0]).hex() != request["domain"] or sid(domain) != self.config["DomainSID"] or bytes(dc["invocationId"][0]).hex() != request["dc"]:
                raise Denied("directory identity changed")
            # One fixed laboratory GUID, never a free DN/filter/operation.
            if request["target"] != self.fixture["Targets"]["casprobe"]:
                raise Denied("unenrolled target")
            guid = "".join("\\%02x" % b for b in bytes.fromhex(request["target"]))
            attributes=list(FIELDS)+["objectGUID","objectSid","uSNChanged","primaryGroupID","userAccountControl","adminCount","memberOf","servicePrincipalName","sIDHistory","msDS-KeyCredentialLink","msDS-AllowedToDelegateTo","msDS-AllowedToActOnBehalfOfOtherIdentity"]
            row = one(self.db, self.config["ManagedOU"], "(objectGUID=" + guid + ")", attributes, ldb.SCOPE_ONELEVEL)
            if sid(row) != request["sid"] or sid(row) in (actor, self.writer_sid) or text(row,"primaryGroupID") != "513" or text(row,"userAccountControl") not in ("512", "514"):
                raise Denied("protected target")
            if text(row,"adminCount","0") != "0" or any(row.get(a) for a in ("memberOf", "servicePrincipalName", "sIDHistory", "msDS-KeyCredentialLink", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity")):
                raise Denied("privileged target")
            if text(row,"uSNChanged") != request["version"]:
                raise Conflict("stale object version")
            if hold is not None:
                hold()
            modify(self.db, row.dn, changes)
            result = one(self.db, row.dn, attrs=["uSNChanged"])
            if fault == "before_commit":
                os._exit(73)
        except BaseException:
            self.db.transaction_cancel()
            record(request, actor, "failed_no_effect")
            raise
        # A commit error is NOT a definitive no-effect result. Leave the durable
        # claim uncertain; never automatically retry it.
        self.db.transaction_commit()
        if fault == "commit_ack_error":
            raise OSError("synthetic commit acknowledgement error")
        if fault == "after_commit":
            os._exit(74)
        record(request, actor, "succeeded")
        return "succeeded"
