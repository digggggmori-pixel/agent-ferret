package collector

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
)

// copyFileSafe copies a file to a temp location, handling locked files.
// Returns the temp path and a cleanup function.
func copyFileSafe(srcPath, prefix string) (string, func(), error) {
	tempCopy := filepath.Join(os.TempDir(), fmt.Sprintf("ferret_%s.db", prefix))
	cleanup := func() { os.Remove(tempCopy) }

	src, err := os.Open(srcPath)
	if err != nil {
		return "", cleanup, fmt.Errorf("open source: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(tempCopy)
	if err != nil {
		return "", cleanup, fmt.Errorf("create temp: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return "", cleanup, fmt.Errorf("copy: %w", err)
	}

	return tempCopy, cleanup, nil
}

// openSQLiteReadOnly opens a SQLite database in read-only mode.
func openSQLiteReadOnly(dbPath string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro&immutable=1", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// querySQLiteRows executes a query and calls rowFn for each row.
func querySQLiteRows(db *sql.DB, query string, rowFn func(*sql.Rows) error) (int, error) {
	rows, err := db.Query(query)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		if err := rowFn(rows); err != nil {
			logger.Debug("SQLite row parse error: %v", err)
			continue
		}
		count++
	}
	return count, rows.Err()
}
