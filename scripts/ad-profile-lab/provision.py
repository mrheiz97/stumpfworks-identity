"""Disposable synthetic AD; only inside the networkless laboratory container."""
import json
import logging
import os
import secrets
import subprocess
import uuid
import ldb
from samba.auth import system_session
from samba.dcerpc import security
from samba.ndr import ndr_pack, ndr_unpack
from samba.provision import provision

os.umask(0o077)
password = secrets.token_urlsafe(32) + "aA1!"
result = provision(logging.getLogger("lab"), system_session(), targetdir="/tmp/profile-domain",
                   realm="PROFILE.TEST", domain="PROFILE", hostname="dc1",
                   hostip="127.0.0.1", adminpass=password,
                   serverrole="active directory domain controller", dns_backend="NONE",
                   useeadb=True, skip_sysvolacl=True, dom_for_fun_level=4)
sam = result.samdb
base = str(sam.domain_dn())
ou = "OU=Managed," + base
sam.create_ou(ou)
sam.create_ou("OU=Outside," + base)
for name in ("writer", "operator", "ordinary", "privileged", "outside", "nested"):
    sam.newuser(name, password, userou="OU=Outside" if name in ("writer", "operator", "outside") else "OU=Managed")
sam.newgroup("Profile Operators")
sam.add_remove_group_members("Profile Operators", ["operator"], add_members_operation=True)
sam.add_remove_group_members("Domain Admins", ["privileged"], add_members_operation=True)
sam.newgroup("Nested Protection")
sam.add_remove_group_members("Nested Protection", ["nested"], add_members_operation=True)
sam.add_remove_group_members("Domain Admins", ["Nested Protection"], add_members_operation=True)

def entry(name):
    return sam.search(base=base, expression="(sAMAccountName=" + name + ")", attrs=["*"])[0]

writer = entry("writer")
writer_sid = str(ndr_unpack(security.dom_sid, writer["objectSid"][0]))
targets = {}
for name in ("ordinary", "privileged", "outside", "nested"):
    user = entry(name)
    targets[name] = bytes(user["objectGUID"][0]).hex()
    if name != "ordinary":
        continue
    sd = sam.search(base=user.dn, scope=ldb.SCOPE_BASE, attrs=["nTSecurityDescriptor"])[0]
    desc = ndr_unpack(security.descriptor, sd["nTSecurityDescriptor"][0])
    for attr in ("displayName", "givenName", "sn", "mail"):
        schema = sam.search(base=sam.get_schema_basedn(), expression="(lDAPDisplayName=" + attr + ")", attrs=["schemaIDGUID"])[0]
        guid = str(uuid.UUID(bytes_le=bytes(schema["schemaIDGUID"][0])))
        ace = security.descriptor.from_sddl("D:(OA;;WP;" + guid + ";;" + writer_sid + ")", security.dom_sid(sam.get_domain_sid())).dacl.aces[0]
        desc.dacl_add(ace)
    msg = ldb.Message(); msg.dn = user.dn
    msg["nTSecurityDescriptor"] = ldb.MessageElement(ndr_pack(desc), ldb.FLAG_MOD_REPLACE, "nTSecurityDescriptor")
    sam.modify(msg)

domain = sam.search(base=base, scope=ldb.SCOPE_BASE, attrs=["objectGUID"])[0]
root = sam.search(base="", scope=ldb.SCOPE_BASE, attrs=["dsServiceName"])[0]
dc = sam.search(base=str(root["dsServiceName"][0]), scope=ldb.SCOPE_BASE, attrs=["invocationId"])[0]
config = dict(Enabled=True, URL="ldaps://dc1.profile.test:636", BaseDN=base,
              ManagedOU=ou, DomainGUID=bytes(domain["objectGUID"][0]).hex(),
              DomainSID=str(sam.get_domain_sid()), DCIdentity=bytes(dc["invocationId"][0]).hex(),
              WriterDN=str(writer.dn), PasswordFile="/tmp/lab-password", CAFile="/tmp/ca.pem",
              OperatorGroupDN=str(entry("Profile Operators").dn), OperatorGroupGUID=bytes(entry("Profile Operators")["objectGUID"][0]).hex(), Revision="lab-stage1-v1",
              Targets=list(targets.values()), ProtectedGUIDs=[])
with open("/tmp/lab-password", "w") as f: f.write(password)
with open("/tmp/lab-config.json", "w") as f: json.dump(dict(Config=config, Targets=targets, Password=password), f)
with open("/etc/hosts", "a") as f: f.write("\n127.0.0.1 dc1.profile.test dc1\n")
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "/tmp/ca.key", "-out", "/tmp/ca.pem", "-days", "2", "-subj", "/CN=Disposable Profile Lab CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "/tmp/dc.key", "-out", "/tmp/dc.csr", "-subj", "/CN=dc1.profile.test"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
with open("/tmp/extensions", "w") as f: f.write("subjectAltName=DNS:dc1.profile.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
subprocess.run(["openssl", "x509", "-req", "-in", "/tmp/dc.csr", "-CA", "/tmp/ca.pem", "-CAkey", "/tmp/ca.key", "-CAcreateserial", "-out", "/tmp/dc.pem", "-days", "2", "-extfile", "/tmp/extensions"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
with open("/tmp/profile-domain/etc/smb.conf", "a") as f:
    f.write("\n[global]\n    interfaces = 127.0.0.1\n    bind interfaces only = yes\n    tls enabled = yes\n    tls keyfile = /tmp/dc.key\n    tls certfile = /tmp/dc.pem\n    tls cafile = /tmp/ca.pem\n")
print("Synthetic domain provisioned; no credentials emitted", flush=True)
