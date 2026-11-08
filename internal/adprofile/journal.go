package adprofile

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// Journal owns a separate executor database. Schema creation is an explicit
// offline command; opening a running executor never performs DDL.
type Journal struct {
	DB   *sql.DB
	aead cipher.AEAD
}
type AuditEvent struct {
	Event    string `json:"event"`
	At       int64  `json:"at"`
	Metadata string `json:"metadata"`
}

func (j *Journal) History(ctx context.Context, id string) ([]AuditEvent, error) {
	rows, e := j.DB.QueryContext(ctx, `SELECT event,happened_at,metadata FROM ad_profile_audit WHERE operation_id=$1 ORDER BY happened_at DESC,event DESC LIMIT 100`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	events := []AuditEvent{}
	for rows.Next() {
		var event AuditEvent
		if rows.Scan(&event.Event, &event.At, &event.Metadata) != nil {
			return nil, ErrDenied
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

const Schema = `CREATE TABLE ad_profile_operations (
 id TEXT PRIMARY KEY, actor TEXT NOT NULL, target TEXT NOT NULL, state TEXT NOT NULL,
 expires BIGINT NOT NULL, parent TEXT NOT NULL, payload TEXT NOT NULL, metadata TEXT NOT NULL,
 CHECK(state IN ('prepared','applying','succeeded','failed_no_effect','cancelled','expired','reconciliation_required','reconciled_effect_observed')));
 CREATE UNIQUE INDEX ad_profile_one_open ON ad_profile_operations(target) WHERE state IN ('prepared','applying','reconciliation_required');
 CREATE TABLE ad_profile_audit (
 operation_id TEXT NOT NULL, actor TEXT NOT NULL, target TEXT NOT NULL,
 event TEXT NOT NULL, happened_at BIGINT NOT NULL, metadata TEXT NOT NULL);
`

func NewJournal(db *sql.DB, key []byte) (*Journal, error) {
	if db == nil {
		return nil, ErrDenied
	}
	block, e := aes.NewCipher(key)
	if e != nil || len(key) != 32 {
		return nil, ErrDenied
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, ErrDenied
	}
	return &Journal{db, aead}, nil
}
func (j *Journal) seal(p Plan) (string, error) {
	b, e := json.Marshal(p)
	if e != nil {
		return "", ErrDenied
	}
	nonce := make([]byte, j.aead.NonceSize())
	if _, e = io.ReadFull(rand.Reader, nonce); e != nil {
		return "", ErrDenied
	}
	return base64.StdEncoding.EncodeToString(j.aead.Seal(nonce, nonce, b, []byte(p.ID))), nil
}
func (j *Journal) Get(ctx context.Context, id string) (Operation, Plan, error) {
	var op Operation
	var encrypted string
	e := j.DB.QueryRowContext(ctx, `SELECT id,actor,target,state,expires,parent,payload FROM ad_profile_operations WHERE id=$1`, id).Scan(&op.ID, &op.Actor, &op.Target, &op.State, &op.Expires, &op.Parent, &encrypted)
	if e != nil {
		return op, Plan{}, e
	}
	if encrypted == "" {
		return op, Plan{}, nil
	}
	b, e := base64.StdEncoding.DecodeString(encrypted)
	n := j.aead.NonceSize()
	if e != nil || len(b) < n {
		return op, Plan{}, ErrDenied
	}
	b, e = j.aead.Open(nil, b[:n], b[n:], []byte(id))
	if e != nil {
		return op, Plan{}, ErrDenied
	}
	var p Plan
	if json.Unmarshal(b, &p) != nil || p.ID != op.ID || p.Actor != op.Actor || p.Target != op.Target || p.Expires != op.Expires || p.Parent != op.Parent || p.Digest != digest(p) {
		return op, Plan{}, ErrDenied
	}
	return op, p, nil
}
func (j *Journal) Prepare(ctx context.Context, p Plan) error {
	payload, e := j.seal(p)
	if e != nil {
		return e
	}
	tx, e := j.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	attrs := []string{}
	for a, v := range p.After.Values {
		if !reflect.DeepEqual(v, p.Before.Values[a]) {
			attrs = append(attrs, a)
		}
	}
	sort.Strings(attrs)
	meta, _ := json.Marshal(struct {
		Action, Policy, Parent string
		Attributes             []string
	}{"profile.modify", p.Policy, p.Parent, attrs})
	if _, e = tx.ExecContext(ctx, `INSERT INTO ad_profile_operations VALUES($1,$2,$3,'prepared',$4,$5,$6,$7)`, p.ID, p.Actor, p.Target, p.Expires, p.Parent, payload, string(meta)); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO ad_profile_audit VALUES($1,$2,$3,'prepared',$4,$5)`, p.ID, p.Actor, p.Target, time.Now().Unix(), string(meta)); e != nil {
		return e
	}
	return tx.Commit()
}
func (j *Journal) Change(ctx context.Context, op Operation, from, to string) error {
	tx, e := j.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.ExecContext(ctx, `UPDATE ad_profile_operations SET state=$1 WHERE id=$2 AND actor=$3 AND target=$4 AND state=$5`, to, op.ID, op.Actor, op.Target, from)
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e != nil || n != 1 {
		return ErrDenied
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO ad_profile_audit SELECT id,actor,target,$2,$3,metadata FROM ad_profile_operations WHERE id=$1`, op.ID, to, time.Now().Unix()); e != nil {
		return e
	}
	return tx.Commit()
}

// Recover runs only at exclusive executor startup. Never requeues a claim.
func (j *Journal) Recover(ctx context.Context) error {
	tx, e := j.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `INSERT INTO ad_profile_audit SELECT id,actor,target,'reconciliation_required',$1,metadata FROM ad_profile_operations WHERE state='applying'`, time.Now().Unix()); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE ad_profile_operations SET state='reconciliation_required' WHERE state='applying'`); e != nil {
		return e
	}
	return tx.Commit()
}

func (j *Journal) Denied(ctx context.Context, id, actor string) error {
	_, e := j.DB.ExecContext(ctx, `INSERT INTO ad_profile_audit VALUES($1,$2,'','denied',$3,'{}')`, id, actor, time.Now().Unix())
	return e
}

// Erase expired terminal compensation data after seven days. Identity, state
// and audit remain durable, so erasure cannot make an operation replayable.
func (j *Journal) Erase(ctx context.Context, now time.Time) error {
	tx, e := j.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	cutoff := now.Add(-7 * 24 * time.Hour).Unix()
	if _, e = tx.ExecContext(ctx, `INSERT INTO ad_profile_audit SELECT id,actor,target,'expired',$1,metadata FROM ad_profile_operations WHERE state='prepared' AND expires<=$1`, now.Unix()); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE ad_profile_operations SET state='expired' WHERE state='prepared' AND expires<=$1`, now.Unix()); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO ad_profile_audit SELECT id,actor,target,'payload_erased',$1,metadata FROM ad_profile_operations WHERE payload<>'' AND expires<$2 AND state NOT IN ('prepared','applying','reconciliation_required')`, now.Unix(), cutoff); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE ad_profile_operations SET payload='' WHERE expires<$1 AND state NOT IN ('prepared','applying','reconciliation_required')`, cutoff); e != nil {
		return e
	}
	return tx.Commit()
}
