package sqlsess

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"

	"github.com/BurntSushi/locker"
)

var (
	SessionLastUpdated = "__sess_last_updated"
	CookieIdName       = "sess_sessionid"
	SqlTableName       = "sess_session"
	SqlCreateSession   = `
	CREATE TABLE ` + SqlTableName + ` IF NOT EXISTS (
		id BYTEA NOT NULL,
		name VARCHAR (255) NOT NULL,
		key TEXT NOT NULL,
		value TEXT NOT NULL,
		PRIMARY KEY (id, name, key)
	)
	`
)

type Store struct {
	*sql.DB
	hashKey, blockKey []byte
}

func Open(db *sql.DB) (*Store, error) {
	if _, err := db.Exec(SqlCreateSession); err != nil {
		return nil, err
	}

	s := &Store{
		DB:       db,
		hashKey:  securecookie.GenerateRandomKey(64),
		blockKey: securecookie.GenerateRandomKey(32),
	}
	return s, nil
}

func (s *Store) Clean(inactive time.Duration) error {
	locker.Lock("clean")
	defer locker.Unlock("clean")

	rows, err := s.Query(`
		SELECT id, value
		FROM ` + SqlTableName + `
		WHERE key = $1
	`, SessionLastUpdated)
	if err != nil {
		return err
	}
	defer rows.Close()

	cutoff := time.Now().UTC().Add(-inactive)
	for rows.Next() {
		var id []byte
		var last string
		if err := rows.Scan(&id, &last); err != nil {
			return err
		}
		lastUp, err := time.Parse(time.RFC3339Nano, last)
		if err != nil {
			return err
		}
		if lastUp.Before(cutoff) {
			_, err = s.Exec(
				"DELETE FROM " + SqlTableName + " WHERE id = $1", id)
			if err != nil {
				return err
			}
		}
	}
	return rows.Err()
}

func (s *Store) Delete(sess *sessions.Session) error {
	id := []byte(sess.ID)
	_, err := s.Exec("DELETE FROM " + SqlTableName + " WHERE id = $1", id)
	return err
}

func (s *Store) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

func (s *Store) New(r *http.Request, name string) (*sessions.Session, error) {
	sess := sessions.NewSession(s, name)
	sess.ID = s.id(r)

	RLock(sess)
	defer RUnlock(sess)

	rows, err := s.Query(`
		SELECT key, value
		FROM ` + SqlTableName + `
		WHERE id = $1 AND name = $2
	`, []byte(sess.ID), name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		sess.Values[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *Store) Save(
	r *http.Request,
	w http.ResponseWriter,
	sess *sessions.Session,
) error {
	Lock(sess)
	defer Unlock(sess)

	s.writeCookie(r, w, CookieIdName, sess.ID)

	id := []byte(sess.ID)
	sess.Values[SessionLastUpdated] = time.Now().UTC()
	tx, err := s.Begin()
	if err != nil {
		return err
	}

	_, err = tx.Exec("DELETE FROM " + SqlTableName + " WHERE id = $1", id)
	if err != nil {
		tx.Rollback()
		return err
	}

	prep, err := tx.Prepare(`
		INSERT INTO ` + SqlTableName + `
			(id, name, key, value) VALUES ($1, $2, $3, $4)
	`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer prep.Close()

	for k, v := range sess.Values {
		if _, err := prep.Exec(id, sess.Name(), k, v); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// id returns either the session id from a user's cookie or generates
// a fresh one if the cookie is inaccessible or missing.
func (s *Store) id(r *http.Request) string {
	id := s.readCookie(r, CookieIdName)
	if len(id) == 0 {
		id = string(securecookie.GenerateRandomKey(64))
	}
	return id
}

// SetKeys sets the hash and block keys used to read and write the session
// cookie. A hash key is required and is used to to authenticate a cookie
// value using HMAC. It's recommend to be 32 or 64 bytes.
//
// A block key is optional and is used to encrypt the cookie value. If it's
// set to nil, then encryption will not be used. This package uses AES, so
// the block key must have length 16, 24 or 32 bytes corresponding to
// AES-128, AES-192 or AES-256. If the block key violates these constraints,
// SetKeys will panic.
//
// This method is exposed so that multiple instantiations of session stores
// can share the same cookie. This particularly useful if you want to be able
// to restart your web server without invalidating existing user sessions.
//
// If this method is not called, then a fresh set of keys is created
// automatically, but will invalidate all existing user sessions.
func (s *Store) SetKeys(hash, block []byte) {
	validLen := len(block) == 16 || len(block) == 24 || len(block) == 32
	if block != nil && !validLen {
		panic("invalid block key")
	}
	s.hashKey, s.blockKey = hash, block
}

func (s *Store) cookrw() *securecookie.SecureCookie {
	return securecookie.New(s.hashKey, s.blockKey)
}

// Returns an empty string if the cookie doesn't exist or if there was
// a problem decoding it.
func (s *Store) readCookie(r *http.Request, cname string) string {
	if cook, err := r.Cookie(cname); err == nil {
		var v string
		if err = s.cookrw().Decode(cname, cook.Value, &v); err == nil {
			return v
		}
	}
	return ""
}

// Writes the value to the named cookie with encryption.
func (s *Store) writeCookie(
	r *http.Request,
	w http.ResponseWriter,
	cname, cvalue string,
) {
	if encoded, err := s.cookrw().Encode(cname, cvalue); err == nil {
		cook := &http.Cookie{
			Name:     cname,
			Value:    encoded,
			Path:     "/",
			HttpOnly: true,
		}
		http.SetCookie(w, cook)
	}
}

func Lock(sess *sessions.Session)    { locker.Lock(sess.ID) }
func Unlock(sess *sessions.Session)  { locker.Unlock(sess.ID) }
func RLock(sess *sessions.Session)   { locker.RLock(sess.ID) }
func RUnlock(sess *sessions.Session) { locker.RUnlock(sess.ID) }
