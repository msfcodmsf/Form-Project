// datahandlers
package datahandlers

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"
)

var DB *sql.DB

type Session struct {
	ID     string
	UserID int
	Expiry time.Time
}

// Veritabanına bağlantı açar.
func SetDB() {
	var err error
	DB, err = sql.Open("sqlite3", "./database/forum.db")
	if err != nil {
		log.Fatal("Error opening database: ", err)
	}
}

// HTTP isteğinden (r) oturum çerezini alarak oturum bilgilerini döndürür.
func GetSession(r *http.Request) (*Session, error) {
	if DB == nil {
		return nil, fmt.Errorf("database connection is not initialized")
	}

	cookie, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			return nil, nil // Çerez bulunamadıysa, oturum yok olarak döndür
		}
		return nil, err // Başka bir hata varsa hata döndür
	}

	sessionToken := cookie.Value

	var session Session
	err = DB.QueryRow("SELECT id, user_id, expiry FROM sessions WHERE id = ?", sessionToken).Scan(&session.ID, &session.UserID, &session.Expiry)
	if err != nil {
		return nil, err
	}

	if session.Expiry.Before(time.Now()) {
		return nil, fmt.Errorf("session expired")
	}

	// Oturum açıldığında, kullanıcının diğer oturumlarını kapat
	_, err = DB.Exec("DELETE FROM sessions WHERE user_id = ? AND id <> ?", session.UserID, sessionToken)
	if err != nil {
		return nil, err
	}

	// Oturum süresini her kontrol ettiğimizde uzatalım
	newExpiry := time.Now().Add(10 * time.Minute)
	_, err = DB.Exec("UPDATE sessions SET expiry = ? WHERE id = ?", newExpiry, sessionToken)
	if err != nil {
		return nil, err
	}
	session.Expiry = newExpiry

	return &session, nil
}

// Gerekli veritabanı tablolarını oluşturur.// datahandlers.go içerisinde

func CreateTables() {
    SessionTables(DB)
    PostTables(DB)
    UsersTables(DB)
    VoteTables(DB)
    CommentTables(DB)
    CreateModeratorRequestsTable(DB)

    // Posts tablosunu oluştur (image_path sütunu ile)
    _, err := DB.Exec(`
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            content TEXT,
            categories TEXT,
            created_at TIMESTAMP,
            image_path TEXT,
            moderated INTEGER DEFAULT 0
        );
    `)
    if err != nil {
        log.Fatal("Error creating posts table:", err)
    }

    // moderator_requests tablosunu oluştur
    _, err = DB.Exec(`
        CREATE TABLE IF NOT EXISTS moderator_requests (
            user_id INTEGER PRIMARY KEY,
            reason TEXT, -- Başvuru nedeni için sütun eklendi
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    `)
    if err != nil {
        log.Fatal("Error creating moderator_requests table:", err)
    }

    

    // reports tablosunu oluştur (content_type sütunu ile)
    _, err = DB.Exec(`
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            moderator_id INTEGER,
            reason TEXT,
            status TEXT DEFAULT 'pending', -- pending, approved, rejected
            FOREIGN KEY(post_id) REFERENCES posts(id),
            FOREIGN KEY(moderator_id) REFERENCES users(id)
        );
    `)
    if err != nil {
        log.Fatal("Error creating reports table:", err)
    }

    // categories tablosunu oluştur
    _, err = DB.Exec(`
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        );
    `)
    if err != nil {
        log.Fatal("Error creating categories table:", err)
    }
}

func CreateReportTables(db *sql.DB) {
    _, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            moderator_id INTEGER,
            reason TEXT,
            status TEXT DEFAULT 'pending',
            FOREIGN KEY(post_id) REFERENCES posts(id),
            FOREIGN KEY(moderator_id) REFERENCES users(id)
        );
    `)
    if err != nil {
        log.Fatal("Error creating reports table:", err)
    }
}

func SessionTables(db *sql.DB) {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            expiry TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );`,
	}

	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			log.Fatal("Query failed: ", err)
		}
	}
}

func PostTables(db *sql.DB) {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            content TEXT,
            categories TEXT,
            created_at TIMESTAMP
        );`,
	}
	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			log.Fatal("Query failed: ", err)
		}
	}
}

func UsersTables(db *sql.DB) {
    queries := []string{
        `CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member' -- Yeni rol sütunu (varsayılan: üye)
        );`,
    }

    for _, query := range queries {
        _, err := db.Exec(query)
        if err != nil {
            log.Fatal("Query failed: ", err)
        }
    }
}


// Like Ve Dislike tablolarını oluştur
func VoteTables(db *sql.DB) { // Sayısını artırır
	queries := []string{
		`CREATE TABLE IF NOT EXISTS votes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			post_id INTEGER,
			comment_id INTEGER,
			vote_type INTEGER CHECK(vote_type IN (1, -1))
		);`,
	}
	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			log.Fatal("Query failed: ", err)
		}
	}
}

func CommentTables(db *sql.DB) {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            user_id INTEGER,
            content TEXT,
            created_at TIMESTAMP
        );`,
	}
	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			log.Fatal("Query failed: ", err)
		}
	}
}

// Session token'ına göre oturum bulma fonksiyonu
func GetSessionFromToken(sessionToken string) (*Session, error) {
    if DB == nil {
        return nil, fmt.Errorf("database connection is not initialized")
    }

    var session Session
    err := DB.QueryRow("SELECT id, user_id, expiry FROM sessions WHERE id = ?", sessionToken).Scan(&session.ID, &session.UserID, &session.Expiry)
    if err != nil {
        return nil, err
    }
	err = DB.QueryRow("SELECT id, user_id, expiry FROM sessions WHERE id = ?", sessionToken).Scan(&session.ID, &session.UserID, &session.Expiry)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, nil // Oturum bulunamazsa nil döndür
        }
        return nil, err 
    }

    if session.Expiry.Before(time.Now()) {
        return nil, fmt.Errorf("session expired")
    }

    return &session, nil
}





func CreateModeratorRequestsTable(db *sql.DB) {
    _, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS moderator_requests (
            user_id INTEGER PRIMARY KEY,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    `)
    if err != nil {
        log.Fatal("Error creating moderator_requests table:", err)
    }
}
