package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

type User struct {
	ID       int
	Email    string
	Username string
	Password string
}

type Post struct {
	ID            int
	UserID        int
	Title         string
	Content       string
	Categories    []string
	CreatedAt     time.Time
	LikeCount     int
	disslikeCount int
}

type Comment struct {
	ID            int
	PostID        int
	UserID        int
	Content       string
	CreatedAt     time.Time
	LikeCount     int
	disslikeCount int
}

type Like struct {
	ID        int
	UserID    int
	PostID    sql.NullInt64
	CommentID sql.NullInt64
}

type Session struct {
	ID     string
	UserID int
	Expiry time.Time
}

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./forum.db")
	if err != nil {
		log.Fatal("Error opening database: ", err)
	}
	defer db.Close()

	createTables()

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/createPost", createPostHandler)
	http.HandleFunc("/createComment", createCommentHandler)
	http.HandleFunc("/like", likeHandler)
	http.HandleFunc("/disslike", disslikeHandler)
	http.HandleFunc("/filter", filterHandler)
	http.HandleFunc("/viewPost", viewPostHandler)

	log.Println("Server started at :8080")
	http.ListenAndServe(":8080", nil)
}

func createTables() {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            username TEXT UNIQUE,
            password TEXT
        );`,
		`CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            content TEXT,
            categories TEXT,
            created_at TIMESTAMP
        );`,
		`CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            user_id INTEGER,
            content TEXT,
            created_at TIMESTAMP
        );`,
		`CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            post_id INTEGER,
            comment_id INTEGER
        );`,
		`CREATE TABLE IF NOT EXISTS disslikes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            post_id INTEGER,
            comment_id INTEGER
        );`,
		`CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            expiry TIMESTAMP
        );`,
	}

	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			log.Fatal("Query failed: ", err)
		}
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	query := `
		SELECT p.id, p.user_id, p.title, p.content, p.created_at,
		       (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
		       (SELECT COUNT(*) FROM disslikes WHERE post_id = p.id) as disslike_count
		FROM posts p
		ORDER BY p.created_at DESC`

	rows, err := db.Query(query)
	if err != nil {
		log.Println("Error querying posts:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		if err := rows.Scan(&post.ID, &post.UserID, &post.Title, &post.Content, &post.CreatedAt, &post.LikeCount, &post.disslikeCount); err != nil {
			log.Println("Error scanning post:", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		posts = append(posts, post)
	}

	tmpl, err := template.ParseFiles("templates/home.html")
	if err != nil {
		log.Println("Error parsing template:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Posts []Post
	}{
		Posts: posts,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Println("Error executing template:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		username := r.FormValue("username")
		password := r.FormValue("password")

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", email, username, hashedPassword)
		if err != nil {
			http.Error(w, "Email or username already taken", http.StatusBadRequest)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	tmpl, _ := template.ParseFiles("templates/register.html")
	tmpl.Execute(w, nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")

		var user User
		err := db.QueryRow("SELECT id, password FROM users WHERE email = ?", email).Scan(&user.ID, &user.Password)
		if err != nil {
			http.Error(w, "Invalid email or password", http.StatusUnauthorized)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			http.Error(w, "Invalid email or password", http.StatusUnauthorized)
			return
		}

		sessionID := uuid.NewString()
		expiry := time.Now().Add(24 * time.Hour)

		_, err = db.Exec("INSERT INTO sessions (id, user_id, expiry) VALUES (?, ?, ?)", sessionID, user.ID, expiry)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    "session_id",
			Value:   sessionID,
			Expires: expiry,
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tmpl, _ := template.ParseFiles("templates/login.html")
	tmpl.Execute(w, nil)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	_, err = db.Exec("DELETE FROM sessions WHERE id = ?", cookie.Value)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "session_id",
		Value:  "",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		title := r.FormValue("title")
		content := r.FormValue("content")
		categories := r.Form["categories"]

		categoriesJSON, err := json.Marshal(categories)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO posts (user_id, title, content, categories, created_at) VALUES (?, ?, ?, ?, ?)",
			session.UserID, title, content, categoriesJSON, time.Now())
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tmpl, _ := template.ParseFiles("templates/createPost.html")
	tmpl.Execute(w, nil)
}

func createCommentHandler(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		postID := r.FormValue("post_id")
		content := r.FormValue("content")

		_, err := db.Exec("INSERT INTO comments (post_id, user_id, content, created_at) VALUES (?, ?, ?, ?)",
			postID, session.UserID, content, time.Now())
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/viewPost?id=%s", postID), http.StatusSeeOther)
		return
	}
}

func likeHandler(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	postID := r.FormValue("post_id")
	commentID := r.FormValue("comment_id")

	if postID != "" {
		_, err = db.Exec("INSERT INTO likes (user_id, post_id) VALUES (?, ?)", session.UserID, postID)
	} else if commentID != "" {
		_, err = db.Exec("INSERT INTO likes (user_id, comment_id) VALUES (?, ?)", session.UserID, commentID)
	}

	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
}

func disslikeHandler(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	postID := r.FormValue("post_id")
	commentID := r.FormValue("comment_id")

	if postID != "" {
		_, err = db.Exec("INSERT INTO disslikes (user_id, post_id) VALUES (?, ?)", session.UserID, postID)
	} else if commentID != "" {
		_, err = db.Exec("INSERT INTO disslikes (user_id, comment_id) VALUES (?, ?)", session.UserID, commentID)
	}

	if err != nil {
		log.Println("Error disliking:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
}

func filterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	category := r.URL.Query().Get("category")
	query := "SELECT id, user_id, title, content, categories, created_at FROM posts"
	args := []interface{}{}

	if category != "" {
		query += " WHERE categories LIKE ?"
		args = append(args, "%"+category+"%")
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		var categories string
		if err := rows.Scan(&post.ID, &post.UserID, &post.Title, &post.Content, &categories, &post.CreatedAt); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		json.Unmarshal([]byte(categories), &post.Categories)
		posts = append(posts, post)
	}

	tmpl, _ := template.ParseFiles("templates/filter.html")
	tmpl.Execute(w, posts)
}

func viewPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	postID := r.URL.Query().Get("id")
	if postID == "" {
		http.Error(w, "Post ID required", http.StatusBadRequest)
		return
	}

	var post Post
	var categories string
	query := `
		SELECT p.id, p.user_id, p.title, p.content, p.categories, p.created_at,
		       (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
		       (SELECT COUNT(*) FROM disslikes WHERE post_id = p.id) as disslike_count
		FROM posts p
		WHERE p.id = ?`

	err := db.QueryRow(query, postID).Scan(&post.ID, &post.UserID, &post.Title, &post.Content, &categories, &post.CreatedAt, &post.LikeCount, &post.disslikeCount)
	if err != nil {
		log.Println("Error querying post:", err)
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}
	json.Unmarshal([]byte(categories), &post.Categories)

	commentQuery := `
		SELECT c.id, c.post_id, c.user_id, c.content, c.created_at,
		       (SELECT COUNT(*) FROM likes WHERE comment_id = c.id) as like_count,
		       (SELECT COUNT(*) FROM disslikes WHERE comment_id = c.id) as disslike_count
		FROM comments c
		WHERE c.post_id = ?`
	rows, err := db.Query(commentQuery, postID)
	if err != nil {
		log.Println("Error querying comments:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var comments []Comment
	for rows.Next() {
		var comment Comment
		if err := rows.Scan(&comment.ID, &comment.PostID, &comment.UserID, &comment.Content, &comment.CreatedAt, &comment.LikeCount, &comment.disslikeCount); err != nil {
			log.Println("Error scanning comment:", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		comments = append(comments, comment)
	}

	data := struct {
		Post     Post
		Comments []Comment
	}{
		Post:     post,
		Comments: comments,
	}

	tmpl, err := template.ParseFiles("templates/viewPost.html")
	if err != nil {
		log.Println("Error parsing template:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Println("Error executing template:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func getSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil, err
	}

	var session Session
	err = db.QueryRow("SELECT id, user_id, expiry FROM sessions WHERE id = ?", cookie.Value).Scan(&session.ID, &session.UserID, &session.Expiry)
	if err != nil {
		return nil, err
	}

	if session.Expiry.Before(time.Now()) {
		_, _ = db.Exec("DELETE FROM sessions WHERE id = ?", session.ID)
		return nil, fmt.Errorf("session expired")
	}

	return &session, nil
}
