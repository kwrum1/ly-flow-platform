package agentidentity

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type tokenStore interface {
	putToken([sha256.Size]byte, tokenRecord) error
	consumeToken([sha256.Size]byte, tokenPurpose, time.Time) (tokenRecord, error)
	restoreToken([sha256.Size]byte) error
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) EnsureSchema(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS agent_identities (
			agent_id TEXT PRIMARY KEY,
			state TEXT NOT NULL,
			legacy_hash BYTEA NOT NULL,
			new_hash BYTEA,
			overlap_until TIMESTAMPTZ,
			http_enabled BOOLEAN NOT NULL DEFAULT true,
			grpc_enabled BOOLEAN NOT NULL DEFAULT false,
			http_confirmed BOOLEAN NOT NULL DEFAULT false,
			grpc_confirmed BOOLEAN NOT NULL DEFAULT false,
			version BIGINT NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE TABLE IF NOT EXISTS agent_identity_tokens (
			token_hash BYTEA PRIMARY KEY,
			agent_id TEXT NOT NULL,
			purpose TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			used BOOLEAN NOT NULL DEFAULT false,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE TABLE IF NOT EXISTS agent_identity_events (
			id BIGSERIAL PRIMARY KEY,
			agent_id TEXT NOT NULL,
			state TEXT NOT NULL,
			version BIGINT NOT NULL,
			occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`)
	if err != nil {
		return fmt.Errorf("ensure agent identity schema: %w", err)
	}
	return nil
}

func (s *PostgresStore) Put(record *Record) error {
	snapshot := record.snapshot()
	var previousState State
	var previousVersion uint64
	lookupErr := s.pool.QueryRow(context.Background(), `SELECT state, version FROM agent_identities WHERE agent_id=$1`, snapshot.ID.String()).Scan(&previousState, &previousVersion)
	if lookupErr != nil && !errors.Is(lookupErr, pgx.ErrNoRows) {
		return fmt.Errorf("load previous agent identity: %w", lookupErr)
	}
	var newHash []byte
	if snapshot.NewHash != [sha256.Size]byte{} {
		newHash = snapshot.NewHash[:]
	}
	tag, err := s.pool.Exec(context.Background(), `
		INSERT INTO agent_identities
			(agent_id, state, legacy_hash, new_hash, overlap_until, http_enabled, grpc_enabled, http_confirmed, grpc_confirmed, version, updated_at)
		VALUES ($1,$2,$3,$4,NULLIF($5, '0001-01-01 00:00:00+00'::timestamptz),$6,$7,$8,$9,$10,NOW())
		ON CONFLICT (agent_id) DO UPDATE SET
			state=EXCLUDED.state, legacy_hash=EXCLUDED.legacy_hash, new_hash=EXCLUDED.new_hash,
			overlap_until=EXCLUDED.overlap_until, http_enabled=EXCLUDED.http_enabled,
			grpc_enabled=EXCLUDED.grpc_enabled, http_confirmed=EXCLUDED.http_confirmed,
			grpc_confirmed=EXCLUDED.grpc_confirmed, version=EXCLUDED.version, updated_at=NOW()
		WHERE agent_identities.version < EXCLUDED.version`,
		snapshot.ID.String(), snapshot.State, snapshot.LegacyHash[:], newHash, snapshot.OverlapUntil,
		snapshot.Enabled.HTTP, snapshot.Enabled.GRPC, snapshot.HTTPConfirmed, snapshot.GRPCConfirmed, snapshot.Version)
	if err != nil {
		return fmt.Errorf("store agent identity: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrStaleVersion
	}
	if snapshot.State != StateBridgeRelease && snapshot.State != StateLegacyVerified {
		if _, err := s.pool.Exec(context.Background(), `UPDATE agents SET agent_key=NULL WHERE uuid=$1`, snapshot.ID.String()); err != nil {
			return fmt.Errorf("retire plaintext agent credential: %w", err)
		}
	}
	if errors.Is(lookupErr, pgx.ErrNoRows) || previousState != snapshot.State || previousVersion != snapshot.Version {
		if _, err := s.pool.Exec(context.Background(), `INSERT INTO agent_identity_events (agent_id, state, version) VALUES ($1,$2,$3)`, snapshot.ID.String(), snapshot.State, snapshot.Version); err != nil {
			return fmt.Errorf("record agent identity telemetry: %w", err)
		}
	}
	return nil
}

func (s *PostgresStore) Get(id AgentID) (*Record, error) {
	var snapshot recordSnapshot
	var rawID string
	var legacyHash, newHash []byte
	err := s.pool.QueryRow(context.Background(), `
		SELECT agent_id, state, legacy_hash, COALESCE(new_hash, ''::bytea),
			COALESCE(overlap_until, '0001-01-01 00:00:00+00'::timestamptz),
			http_enabled, grpc_enabled, http_confirmed, grpc_confirmed, version
		FROM agent_identities WHERE agent_id=$1`, id.String()).Scan(
		&rawID, &snapshot.State, &legacyHash, &newHash, &snapshot.OverlapUntil,
		&snapshot.Enabled.HTTP, &snapshot.Enabled.GRPC, &snapshot.HTTPConfirmed, &snapshot.GRPCConfirmed, &snapshot.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAgentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load agent identity: %w", err)
	}
	if len(legacyHash) != sha256.Size || (len(newHash) != 0 && len(newHash) != sha256.Size) {
		return nil, ErrInvalidCredential
	}
	snapshot.ID = id
	copy(snapshot.LegacyHash[:], legacyHash)
	copy(snapshot.NewHash[:], newHash)
	return recordFromSnapshot(snapshot), nil
}

func (s *PostgresStore) putToken(hash [sha256.Size]byte, record tokenRecord) error {
	_, err := s.pool.Exec(context.Background(), `
		INSERT INTO agent_identity_tokens (token_hash, agent_id, purpose, expires_at, used, updated_at)
		VALUES ($1,$2,$3,$4,false,NOW())
		ON CONFLICT (token_hash) DO NOTHING`,
		hash[:], record.id.String(), record.purpose, record.expiresAt)
	if err != nil {
		return fmt.Errorf("store agent token: %w", err)
	}
	return nil
}

func (s *PostgresStore) consumeToken(hash [sha256.Size]byte, purpose tokenPurpose, now time.Time) (tokenRecord, error) {
	var rawID string
	var expiresAt time.Time
	err := s.pool.QueryRow(context.Background(), `
		UPDATE agent_identity_tokens SET used=true, updated_at=NOW()
		WHERE token_hash=$1 AND purpose=$2 AND used=false AND expires_at >= $3
		RETURNING agent_id, expires_at`, hash[:], purpose, now).Scan(&rawID, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		var used bool
		var storedExpiry time.Time
		lookupErr := s.pool.QueryRow(context.Background(), `SELECT used, expires_at FROM agent_identity_tokens WHERE token_hash=$1 AND purpose=$2`, hash[:], purpose).Scan(&used, &storedExpiry)
		switch {
		case errors.Is(lookupErr, pgx.ErrNoRows):
			return tokenRecord{}, ErrTokenUnknown
		case lookupErr != nil:
			return tokenRecord{}, fmt.Errorf("load agent token: %w", lookupErr)
		case used:
			return tokenRecord{}, ErrTokenUsed
		default:
			return tokenRecord{}, ErrTokenExpired
		}
	}
	if err != nil {
		return tokenRecord{}, fmt.Errorf("consume agent token: %w", err)
	}
	id, err := NewAgentID(rawID)
	if err != nil {
		return tokenRecord{}, err
	}
	return tokenRecord{id: id, purpose: purpose, expiresAt: expiresAt, used: true}, nil
}

func (s *PostgresStore) enrollAtomic(ctx context.Context, hash [sha256.Size]byte, credential string, enabled EnabledTransports, now time.Time) (*Record, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin agent enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	token, err := consumeTokenTx(ctx, tx, hash, tokenEnrollment, now)
	if err != nil {
		return nil, err
	}
	record, err := NewLegacyRecord(token.id, credential, enabled)
	if err != nil {
		return nil, err
	}
	snapshot := record.snapshot()
	tag, err := tx.Exec(ctx, `
		INSERT INTO agent_identities
			(agent_id, state, legacy_hash, new_hash, overlap_until, http_enabled, grpc_enabled, http_confirmed, grpc_confirmed, version, updated_at)
		VALUES ($1,$2,$3,NULL,NULL,$4,$5,false,false,$6,NOW())
		ON CONFLICT (agent_id) DO UPDATE SET
			state=EXCLUDED.state, legacy_hash=EXCLUDED.legacy_hash, new_hash=NULL,
			overlap_until=NULL, http_enabled=EXCLUDED.http_enabled,
			grpc_enabled=EXCLUDED.grpc_enabled, http_confirmed=false,
			grpc_confirmed=false, version=EXCLUDED.version, updated_at=NOW()
		WHERE agent_identities.version < EXCLUDED.version`,
		snapshot.ID.String(), snapshot.State, snapshot.LegacyHash[:], snapshot.Enabled.HTTP, snapshot.Enabled.GRPC, snapshot.Version)
	if err != nil {
		return nil, fmt.Errorf("store agent enrollment identity: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrStaleVersion
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_identity_events (agent_id, state, version) VALUES ($1,$2,$3)`, snapshot.ID.String(), snapshot.State, snapshot.Version); err != nil {
		return nil, fmt.Errorf("record agent enrollment telemetry: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit agent enrollment: %w", err)
	}
	return record, nil
}

func consumeTokenTx(ctx context.Context, tx pgx.Tx, hash [sha256.Size]byte, purpose tokenPurpose, now time.Time) (tokenRecord, error) {
	var rawID string
	var expiresAt time.Time
	err := tx.QueryRow(ctx, `
		UPDATE agent_identity_tokens SET used=true, updated_at=NOW()
		WHERE token_hash=$1 AND purpose=$2 AND used=false AND expires_at >= $3
		RETURNING agent_id, expires_at`, hash[:], purpose, now).Scan(&rawID, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		var used bool
		var storedExpiry time.Time
		lookupErr := tx.QueryRow(ctx, `SELECT used, expires_at FROM agent_identity_tokens WHERE token_hash=$1 AND purpose=$2`, hash[:], purpose).Scan(&used, &storedExpiry)
		switch {
		case errors.Is(lookupErr, pgx.ErrNoRows):
			return tokenRecord{}, ErrTokenUnknown
		case lookupErr != nil:
			return tokenRecord{}, fmt.Errorf("load agent token: %w", lookupErr)
		case used:
			return tokenRecord{}, ErrTokenUsed
		default:
			return tokenRecord{}, ErrTokenExpired
		}
	}
	if err != nil {
		return tokenRecord{}, fmt.Errorf("consume agent token: %w", err)
	}
	id, err := NewAgentID(rawID)
	if err != nil {
		return tokenRecord{}, err
	}
	return tokenRecord{id: id, purpose: purpose, expiresAt: expiresAt, used: true}, nil
}

func (s *PostgresStore) restoreToken(hash [sha256.Size]byte) error {
	_, err := s.pool.Exec(context.Background(), `UPDATE agent_identity_tokens SET used=false, updated_at=NOW() WHERE token_hash=$1`, hash[:])
	if err != nil {
		return fmt.Errorf("restore agent token: %w", err)
	}
	return nil
}
