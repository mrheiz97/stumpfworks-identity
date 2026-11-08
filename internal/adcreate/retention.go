package adcreate

import (
	"context"
	"errors"
	"time"
)

var ErrMaintenanceBusy = errors.New("create journal maintenance busy")

// Maintain expires undispatched plans and removes old terminal payloads. The
// operation IDs and successful name reservations remain permanent replay fences.
func (s *Service) Maintain(ctx context.Context, now time.Time) error {
	if s.RecoveryOnly {
		return ErrDenied
	}
	if !s.mu.TryLock() {
		return ErrMaintenanceBusy
	}
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,actor,payload FROM create_ops WHERE state='prepared'`)
	if err != nil {
		return err
	}
	var expired []Plan
	for rows.Next() {
		var id, actor string
		var ciphertext []byte
		var plan Plan
		if rows.Scan(&id, &actor, &ciphertext) != nil || s.open(id, ciphertext, &plan) != nil || plan.ID != id || plan.Actor != actor || plan.Scope != s.Scope || plan.Digest != digest(plan) || !validInput(plan.Input) {
			rows.Close()
			return ErrDenied
		}
		if plan.Expires <= now.Unix() {
			expired = append(expired, plan)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, plan := range expired {
		if _, err = tx.ExecContext(ctx, `UPDATE create_ops SET state='expired' WHERE id=?`, plan.ID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM create_names WHERE id=?`, plan.ID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO create_audit VALUES(?,?,'expired',?)`, plan.ID, plan.Actor, now.Unix()); err != nil {
			return err
		}
	}
	// Require a matching terminal audit event. Missing evidence never licenses erasure.
	const oldTerminal = `SELECT o.id FROM create_ops o WHERE o.state IN ('succeeded','expired','cancelled') AND length(o.payload)>0
	 AND (SELECT MAX(a.at) FROM create_audit a WHERE a.id=o.id AND a.actor=o.actor
	 AND (a.event=o.state OR (o.state='cancelled' AND a.event='handoff_cancelled')))<=?`
	cutoff := now.Add(-7 * 24 * time.Hour).Unix()
	if _, err = tx.ExecContext(ctx, `INSERT INTO create_audit SELECT id,actor,'payload_erased',? FROM create_ops WHERE id IN (`+oldTerminal+`)`, now.Unix(), cutoff); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM create_dispatch WHERE id IN (`+oldTerminal+`)`, cutoff); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE create_ops SET payload=x'',result=NULL WHERE id IN (`+oldTerminal+`)`, cutoff); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM create_audit WHERE at<=? AND (id='' OR id IN (SELECT id FROM create_ops WHERE length(payload)=0 AND state IN ('succeeded','expired','cancelled')))`, now.Add(-90*24*time.Hour).Unix()); err != nil {
		return err
	}
	return tx.Commit()
}
