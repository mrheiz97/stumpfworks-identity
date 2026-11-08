package adprofile

// Only this synthetic adapter can execute the new service's Create operation.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/TheRealHZL/stumpfworks-identity/internal/adcreate"
	adminauth "github.com/TheRealHZL/stumpfworks-identity/internal/auth"
	"github.com/TheRealHZL/stumpfworks-identity/internal/directory"
	ldap "github.com/go-ldap/ldap/v3"
)

type createLabDirectory struct {
	*NativeCreate
	sends      int
	lose       bool
	diagnostic string
}

func (d *createLabDirectory) Create(ctx context.Context, b adcreate.BoundRequest) (adcreate.Result, error) {
	d.sends++
	result, e := d.NativeCreate.Create(ctx, b)
	if e != nil {
		d.diagnostic = nativeErrorCode(e)
	}
	if e == nil && d.lose {
		return adcreate.Result{}, ErrUncertain
	}
	return result, e
}

func TestCreateReceiptValidation(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	q := make([]byte, 248)
	copy(q, "SWCSTAT1")
	q[88] = 1
	binary.BigEndian.PutUint64(q[232:240], 1000)
	binary.BigEndian.PutUint64(q[240:248], 1030)
	body := make([]byte, 366)
	copy(body, "SWCRECP1")
	copy(body[8:256], q)
	body[256] = 2
	binary.BigEndian.PutUint64(body[257:265], 42)
	body[265] = 1
	rawsid := []byte{1, 5, 0, 0, 0, 0, 0, 5}
	for _, n := range []uint32{21, 1, 2, 3, 1000} {
		rawsid = binary.LittleEndian.AppendUint32(rawsid, n)
	}
	body[281] = byte(len(rawsid))
	copy(body[282:350], rawsid)
	binary.BigEndian.PutUint64(body[350:358], 1000)
	binary.BigEndian.PutUint64(body[358:366], 1030)
	sign := func(b []byte) []byte { return append(append([]byte{}, b...), ed25519.Sign(key, b)...) }
	valid := sign(body)
	if _, e := verifyCreateReceipt(valid, q, pub, "S-1-5-21-1-2-3", 1001); e != nil {
		t.Fatal("valid receipt")
	}
	if _, e := verifyCreateReceipt(valid, q, wrong, "S-1-5-21-1-2-3", 1001); e == nil {
		t.Fatal("wrong key")
	}
	q2, body2 := bytes.Clone(q), bytes.Clone(body)
	q2[7], body2[7] = '2', '2'
	copy(body2[8:256], q2)
	if _, e := verifyCreateReceipt(sign(body2), q2, pub, "S-1-5-21-1-2-3", 1001); e != nil {
		t.Fatal("valid v2 receipt", e)
	}
	body2[7] = '1'
	if _, e := verifyCreateReceipt(sign(body2), q2, pub, "S-1-5-21-1-2-3", 1001); e == nil {
		t.Fatal("receipt protocol downgrade")
	}
	if _, e := verifyCreateReceipt(valid, q, pub, "S-1-5-21-9-9-9", 1001); e == nil {
		t.Fatal("foreign SID")
	}
	if _, e := verifyCreateReceipt(valid, q, pub, "S-1-5-21-1-2-3", 1030); e == nil {
		t.Fatal("expired")
	}
	replay := append([]byte{}, q...)
	replay[88] ^= 2
	if _, e := verifyCreateReceipt(valid, replay, pub, "S-1-5-21-1-2-3", 1001); e == nil {
		t.Fatal("nonce replay")
	}
	for _, offset := range []int{0, 8, 88, 104, 168, 200, 256, 281, 282, 345, 350, 358} {
		changed := append([]byte{}, body...)
		changed[offset] ^= 1
		if _, e := verifyCreateReceipt(sign(changed), q, pub, "S-1-5-21-1-2-3", 1001); e == nil {
			t.Fatalf("signed semantic mutation %d", offset)
		}
	}
}

func createFixturePaths() (dir, config string, epoch uint64) {
	if os.Getenv("IDENTITY_CREATE_V2_LAB") == "1" {
		return "/tmp/native-cas-dc2", "/tmp/native-cas-dc2/identity-fixture.json", 2
	}
	return "/tmp/native-cas", "/tmp/lab-config.json", 0
}

func TestCreateIdentityLab(t *testing.T) {
	if os.Getenv("IDENTITY_NATIVE_CREATE_LAB") != "1" {
		t.Skip("isolated create lab only")
	}
	path, fixturePath, epoch := createFixturePaths()
	data, e := os.ReadFile(fixturePath)
	if e != nil {
		t.Fatal(e)
	}
	var f struct{ Config Config }
	if json.Unmarshal(data, &f) != nil {
		t.Fatal("fixture")
	}
	base, e := NewLDAP(f.Config)
	if e != nil {
		t.Fatal(e)
	}
	webDirectory := directory.LDAP{URL: f.Config.URL, BaseDN: f.Config.BaseDN, BindDN: f.Config.WriterDN, BindPassword: base.password, Domain: "profile.test", CAFile: f.Config.CAFile, UserCreatorGroupDN: f.Config.OperatorGroupDN, UserCreatorGroupGUID: f.Config.OperatorGroupGUID}
	if !webDirectory.UserCreationSessionsAllowed() {
		t.Fatal("strict AD session prerequisites")
	}
	authenticated, webRoles, e := webDirectory.AuthenticateAdministrative(context.Background(), "operator", base.password)
	if e != nil || authenticated.Username != "operator" || !adminauth.Allowed(adminauth.PermissionDirectoryUsersCreate, webRoles...) || adminauth.Allowed(adminauth.PermissionIdentityWrite, webRoles...) {
		t.Fatal("real AD creation session mapping", e)
	}
	if base.Ready(context.Background()) == nil {
		t.Fatal("runtime CAS gate opened")
	}
	var pins nativePins
	b, _ := os.ReadFile(path + "/pins.json")
	if json.Unmarshal(b, &pins) != nil {
		t.Fatal("pins")
	}
	b, _ = os.ReadFile(path + "/issuer.pem")
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("key")
	}
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		t.Fatal("key")
	}
	b, _ = os.ReadFile(path + "/create-ou")
	adapter, scope, e := NewNativeCreate(f.Config, CreatePins{ActorGUID: pins.ActorGUID, ActorSID: pins.ActorSID, WriterGUID: pins.WriterGUID, ReceiptPublic: pins.ReceiptPublic, Scope: pins.Scope, Epoch: epoch}, string(b), key.(ed25519.PrivateKey))
	if e != nil {
		t.Fatal(e)
	}
	d := &createLabDirectory{NativeCreate: adapter}
	db, e := sql.Open("sqlite", path+"/create-identity.db")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, e = db.Exec(adcreate.Schema); e != nil {
		t.Fatal(e)
	}
	journalKey := make([]byte, 32)
	rand.Read(journalKey)
	service, e := adcreate.New(db, journalKey, scope, d)
	if e != nil {
		t.Fatal(e)
	}
	service.Enabled = true
	if _, e = service.Prepare(context.Background(), "profileonly", base.password, adcreate.Input{Name: "notallowed", DisplayName: "Not Allowed"}); e == nil {
		t.Fatal("profile role inherited create permission")
	}
	handler := adcreate.Handler{Service: service, Session: func(*http.Request) (string, string, error) { return "operator", "lab-csrf", nil }}
	post := func(values url.Values) *httptest.ResponseRecorder {
		values.Set("_csrf", "lab-csrf")
		values.Set("password", base.password)
		r := httptest.NewRequest("POST", "https://identity.test/create", strings.NewReader(values.Encode()))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://identity.test")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 200 || strings.Contains(w.Body.String(), base.password) {
			t.Fatal("unsafe handler response")
		}
		return w
	}
	w := post(url.Values{"action": {"prepare"}, "name": {"newuser"}, "display": {"New User"}})
	if !strings.Contains(w.Body.String(), "Plan verbindlich bestätigen") || d.sends != 0 {
		t.Fatal("plan UI")
	}
	var id string
	if db.QueryRow(`SELECT id FROM create_ops`).Scan(&id) != nil {
		t.Fatal("plan missing")
	}
	op, e := service.Action(context.Background(), "operator", base.password, id, "status", "")
	if e != nil {
		t.Fatal(e)
	}
	if epoch != 0 {
		if scope.Epoch != epoch || scope.UPNSuffix != "managed.profile.test" ||
			!strings.Contains(w.Body.String(), "newuser@managed.profile.test") {
			t.Fatal("managed UPN plan")
		}
		testCreateEpochBinding(t, d.NativeCreate, op.Plan)
	}
	if _, e = service.Action(context.Background(), "operator", base.password, id, "confirm", "tampered"); e == nil || d.sends != 0 {
		t.Fatal("confirmation bypass")
	}
	// Valid issuer signature with wrong scope or altered signature cannot reach Add.
	bad := d.frame(op.Plan)
	bad[len(bad)-1] ^= 1
	if d.send(context.Background(), op.Plan, bad) == nil {
		t.Fatal("tamper")
	}
	other := op.Plan
	other.Scope.OU = strings.Repeat("0", 32)
	if d.send(context.Background(), op.Plan, d.frame(other)) == nil {
		t.Fatal("scope")
	}
	w = post(url.Values{"action": {"confirm"}, "id": {id}, "digest": {op.Plan.Digest}})
	if !strings.Contains(w.Body.String(), "Deaktiviertes Konto bestätigt angelegt") || d.sends != 1 {
		t.Fatal("creation failed code=" + d.diagnostic)
	}
	_, e = service.Action(context.Background(), "operator", base.password, id, "confirm", op.Plan.Digest)
	if e == nil || d.sends != 1 {
		t.Fatal("replay")
	}
	// Writer cannot bypass native template with plain LDAP or change new account.
	c, e := base.connect(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	raw := ldap.NewAddRequest("CN=raw,"+f.Config.ManagedOU, nil)
	raw.Attribute("objectClass", []string{"user"})
	raw.Attribute("sAMAccountName", []string{"raw"})
	raw.Attribute("userAccountControl", []string{"512"})
	if c.Add(raw) == nil {
		t.Fatal("raw Add")
	}
	mod := ldap.NewModifyRequest("CN=newuser,"+f.Config.ManagedOU, nil)
	mod.Replace("userAccountControl", []string{"512"})
	if c.Modify(mod) == nil {
		t.Fatal("activation")
	}
	if c.Del(ldap.NewDelRequest("CN=newuser,"+f.Config.ManagedOU, nil)) == nil {
		t.Fatal("automatic delete authority")
	}
	events, e := service.History(context.Background(), "operator", base.password, id)
	if e != nil || len(events) != 6 {
		t.Fatal("audit")
	}
	// Lost LDAP response after real native commit keeps names/ID blocked on reopen.
	runCreateTransportLab(t, service, base.password)
	if d.sends != 2 {
		t.Fatal("unexpected transport dispatch count")
	}
	second, e := service.Prepare(context.Background(), "operator", base.password, adcreate.Input{Name: "lostuser", DisplayName: "Lost User"})
	if e != nil {
		t.Fatal(e)
	}
	d.lose = true
	_, e = service.Action(context.Background(), "operator", base.password, second.Plan.ID, "confirm", second.Plan.Digest)
	if !errors.Is(e, adcreate.ErrUncertain) {
		t.Fatal("lost reply")
	}
	freshDirectory := &createLabDirectory{NativeCreate: adapter}
	if db.Close() != nil {
		t.Fatal("close journal")
	}
	reopenedDB, e := sql.Open("sqlite", path+"/create-identity.db")
	if e != nil {
		t.Fatal(e)
	}
	defer reopenedDB.Close()
	reopenedDB.SetMaxOpenConns(1)
	reopened, e := adcreate.New(reopenedDB, journalKey, scope, freshDirectory)
	if e != nil {
		t.Fatal(e)
	}
	reopened.Enabled = true
	observed, e := reopened.Action(context.Background(), "operator", base.password, second.Plan.ID, "evidence", "")
	if e != nil || observed.Evidence == nil || observed.State != "uncertain" || freshDirectory.sends != 0 {
		t.Fatal("durable native evidence after new adapter", e)
	}
	// Current role revocation must block receipt access even with a valid session/password.
	admin, e := base.connect(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	if admin.Bind("CN=Administrator,CN=Users,"+f.Config.BaseDN, base.password) != nil {
		t.Fatal("fixture admin")
	}
	group, e := one(admin, f.Config.OperatorGroupDN, ldap.ScopeBaseObject, "(objectClass=group)", []string{"member"})
	if e != nil {
		t.Fatal(e)
	}
	change := ldap.NewModifyRequest(group.DN, nil)
	change.Replace("member", nil)
	if admin.Modify(change) != nil {
		t.Fatal("fixture revoke")
	}
	_, revokedRoleError := webDirectory.AdministrativeRoles(context.Background(), "operator")
	_, denied := reopened.Action(context.Background(), "operator", base.password, second.Plan.ID, "evidence", "")
	restore := ldap.NewModifyRequest(group.DN, nil)
	restore.Replace("member", group.GetAttributeValues("member"))
	if admin.Modify(restore) != nil {
		t.Fatal("fixture restore")
	}
	if denied == nil || revokedRoleError == nil || freshDirectory.sends != 0 {
		t.Fatal("role revocation bypass")
	}

	_, e = reopened.Action(context.Background(), "operator", base.password, second.Plan.ID, "confirm", second.Plan.Digest)
	if e == nil || d.sends != 3 {
		t.Fatal("uncertain replay")
	}
	if _, e = reopened.Prepare(context.Background(), "operator", base.password, adcreate.Input{Name: "lostuser", DisplayName: "Duplicate"}); e == nil {
		t.Fatal("duplicate")
	}
	t.Log("real Identity HTML plan/confirmation, native disabled Add, audit, tamper/raw-path guards, lost reply and durable no replay passed; runtime CAS remains blocked")
}

func testCreateEpochBinding(t *testing.T, d *NativeCreate, plan adcreate.Plan) {
	t.Helper()
	ctx := context.Background()
	wire, err := d.Encode(ctx, plan)
	if err != nil || string(wire.Bytes[:8]) != "SWNEW002" || binary.BigEndian.Uint64(wire.Bytes[200:208]) != plan.Scope.Epoch {
		t.Fatal("signed v2 epoch frame", err)
	}
	for _, epoch := range []uint64{0, plan.Scope.Epoch - 1} {
		stale := plan
		stale.Scope.Epoch = epoch
		frame := d.frame(stale)
		hash := sha256.Sum256(frame)
		bound := adcreate.BoundRequest{Plan: plan, Wire: adcreate.Wire{Bytes: frame, Expires: int64(binary.BigEndian.Uint64(frame[128:136]))}, WireDigest: hex.EncodeToString(hash[:])}
		if d.validateBound(bound, false) == nil {
			t.Fatal("alternate epoch or downgrade accepted locally")
		}
		if d.send(ctx, plan, frame) == nil {
			t.Fatal("alternate epoch or downgrade accepted by Samba")
		}
	}
}
