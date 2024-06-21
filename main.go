package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	db       *sql.DB
	validate *validator.Validate
	config   Config
)

type Config struct {
	GoogleClientID     string `json:"google_client_id"`
	GoogleClientSecret string `json:"google_client_secret"`
}

func loadConfig() {
	file, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("Failed to open config file: %s", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		log.Fatalf("Failed to decode config file: %s", err)
	}
}

var googleOauthConfig *oauth2.Config

func init() {
	loadConfig()
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8065/google/callback",
		ClientID:     config.GoogleClientID,
		ClientSecret: config.GoogleClientSecret,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}

type User struct {
	ID       int            `validate:"-"`
	Email    string         `validate:"required,email"`
	Username sql.NullString `validate:"omitempty,alphanum,min=3,max=20"`
	Password sql.NullString `validate:"omitempty,min=6"`
}

type Post struct {
	ID                  int
	UserID              int
	Title               string
	Content             string
	Categories          []string // JSON olarak kaydedilecek ve geri okunacak
	CategoriesFormatted string   // Virgülle ayrılmış kategoriler
	CreatedAt           time.Time
	CreatedAtFormatted  string
	LikeCount           int
	DislikeCount        int
	Username            string
	CommentCount        int
}

type Comment struct {
	ID                 int
	PostID             int
	UserID             int
	Content            string
	CreatedAt          time.Time
	CreatedAtFormatted string
	LikeCount          int
	DislikeCount       int
	Username           string // Kullanıcı adı
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

type RegisterTemplateData struct {
	ErrorMessages map[string]string
	Email         string
	Username      string
}

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./forum.db")
	if err != nil {
		log.Fatal("Error opening database: ", err)
	}
	defer db.Close()

	validate = validator.New()

	createTables()
	//Bu örnek, sadece static/ dizinindeki dosyaların sunulmasını sağlar ve güvenlik risklerini azaltır.
	http.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[1:]
		if !strings.HasPrefix(path, "static/") {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, path)
	})

	http.HandleFunc("/google/login", handleGoogleLogin)
	http.HandleFunc("/google/callback", handleGoogleCallback)

	// http.HandleFunc("/github/login", handleGitHubLogin)
	// http.HandleFunc("/github/callback", handleGitHubCallback)

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/sifreunut", sifreUnutHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/createPost", createPostHandler)
	http.HandleFunc("/createComment", createCommentHandler)
	http.HandleFunc("/deletePost", deletePostHandler)
	http.HandleFunc("/deleteComment", deleteCommentHandler)
	http.HandleFunc("/vote", voteHandler)
	http.HandleFunc("/viewPost", viewPostHandler)
	http.HandleFunc("/myprofil", myProfileHandler)
	http.HandleFunc("/get_most_liked_posts", getMostLikedPosts)
	log.Println("Server started at :8065")
	http.ListenAndServe(":8065", nil)
}

func handleErr(w http.ResponseWriter, err error, userMessage string, code int) {
	log.Printf("Error: %v", err)
	http.Error(w, userMessage, code)
}

func createTables() {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
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
		`CREATE TABLE IF NOT EXISTS Dislikes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            post_id INTEGER,
            comment_id INTEGER
        );`,
		`CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            expiry TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );`,
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

func homeHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := getSession(r) // Kullanıcının oturum bilgilerini alır

    sortBy := r.URL.Query().Get("sortBy")     // Sıralama parametresini alır (mostliked, mostcommented veya varsayılan)
    searchQuery := r.URL.Query().Get("search") // Arama sorgusunu alır
    category := r.URL.Query().Get("category")   // Kategori filtresini alır

    posts, err := getFilteredPosts(searchQuery, category, sortBy) // Filtrelenmiş ve sıralanmış gönderileri alır
    if err != nil {
        handleErr(w, err, "Internal server error", http.StatusInternalServerError) // Hata durumunda hata mesajı gösterir
        return
    }

    tmpl, err := template.ParseFiles("templates/index.html") // index.html şablonunu ayrıştırır
    if err != nil {
        handleErr(w, err, "Error parsing template", http.StatusInternalServerError) // Hata durumunda hata mesajı gösterir
        return
    }

    // Şablona gönderilecek verileri hazırlar
    data := struct {
        Posts            []Post   // Gönderi listesi
        LoggedIn         bool     // Kullanıcının oturum açıp açmadığı bilgisi
        SortByMostLiked  bool     // Beğeni sayısına göre sıralama aktif mi?
        SortByMostCommented bool // Yorum sayısına göre sıralama aktif mi?
        SearchQuery      string   // Arama sorgusu
        SelectedCategory string   // Seçili kategori
    }{
        Posts:            posts,
        LoggedIn:         session != nil,
        SortByMostLiked:  sortBy == "mostliked",
        SortByMostCommented: sortBy == "mostcommented",
        SearchQuery:      searchQuery,
        SelectedCategory: category,
    }

    err = tmpl.Execute(w, data) // Şablonu işleyerek HTML çıktısını oluşturur ve gönderir
    if err != nil {
        handleErr(w, err, "Error executing template", http.StatusInternalServerError) // Hata durumunda hata mesajı gösterir
    }
}



func registerHandler(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err == nil && session != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		username := r.FormValue("username")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")

		var user User
		user.Email = email
		user.Username = sql.NullString{
			String: username,
			Valid:  username != "",
		}
		user.Password = sql.NullString{
			String: password,
			Valid:  password != "",
		}

		err := validate.Struct(user)
		if err != nil {
			if _, ok := err.(validator.ValidationErrors); ok {
				errorMessages := make(map[string]string)
				for _, err := range err.(validator.ValidationErrors) {
					switch err.Field() {
					case "Username":
						errorMessages[err.Field()] = "Username must be alphanumeric and between 3 and 20 characters long."
					case "Password":
						errorMessages[err.Field()] = "Password must be at least 6 characters long."
					case "Email":
						errorMessages[err.Field()] = "Invalid email format."
					default:
						errorMessages[err.Field()] = fmt.Sprintf("Field validation for '%s' failed on the '%s' tag", err.Field(), err.Tag())
					}
				}
				renderRegisterTemplate(w, RegisterTemplateData{
					ErrorMessages: errorMessages,
					Email:         email,
					Username:      username,
				})
				return
			}
			handleErr(w, err, "Invalid input", http.StatusBadRequest)
			return
		}

		if password != confirmPassword {
			errorMessages := make(map[string]string)
			errorMessages["ConfirmPassword"] = "Password and confirm password do not match."
			renderRegisterTemplate(w, RegisterTemplateData{
				ErrorMessages: errorMessages,
				Email:         email,
				Username:      username,
			})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			handleErr(w, err, "Internal server error", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", email, username, hashedPassword)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				handleErr(w, err, "Email or username already taken", http.StatusBadRequest)
			} else {
				handleErr(w, err, "Internal server error", http.StatusInternalServerError)
			}
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	renderRegisterTemplate(w, RegisterTemplateData{})
}

func renderRegisterTemplate(w http.ResponseWriter, data RegisterTemplateData) {
	tmpl, err := template.ParseFiles("templates/register.html")
	if err != nil {
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err == nil && session != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")

		var id int
		var hashedPassword string
		err := db.QueryRow("SELECT id, password FROM users WHERE email = ?", email).Scan(&id, &hashedPassword)
		if err != nil {
			handleErr(w, err, "Invalid email or password", http.StatusUnauthorized)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			handleErr(w, err, "Invalid email or password", http.StatusUnauthorized)
			return
		}

		sessionToken := uuid.New().String()
		expiresAt := time.Now().Add(10 * time.Minute)

		_, err = db.Exec("INSERT INTO sessions (id, user_id, expiry) VALUES (?, ?, ?)", sessionToken, id, expiresAt)
		if err != nil {
			handleErr(w, err, "Internal server error", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Expires:  expiresAt,
			HttpOnly: true,
			Secure:   true, // Ensure this is set when using HTTPS
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	sessionToken := cookie.Value
	_, err = db.Exec("DELETE FROM sessions WHERE id = ?", sessionToken)
	if err != nil {
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Now().Add(-1 * time.Second),
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	// Kullanıcının oturumunu kontrol et
	session, err := getSession(r)
	if err != nil || session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Eğer HTTP metodu POST ise gönderi oluşturma işlemi
	if r.Method == http.MethodPost {
		title := r.FormValue("title")
		content := r.FormValue("content")
		categoriesJSON := r.FormValue("categories")

		var categories []string
		err := json.Unmarshal([]byte(categoriesJSON), &categories)
		if err != nil {
			handleErr(w, err, "Invalid categories format", http.StatusBadRequest)
			return
		}

		categoriesData, err := json.Marshal(categories)
		if err != nil {
			handleErr(w, err, "Internal server error", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO posts (user_id, title, content, categories, created_at) VALUES (?, ?, ?, ?, ?)",
			session.UserID, title, content, string(categoriesData), time.Now())
		if err != nil {
			handleErr(w, err, "Internal server error", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Eğer HTTP metodu GET ise formu render et
	tmpl, err := template.ParseFiles("templates/createPost.html")
	if err != nil {
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, nil)
	if err != nil {
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
	}
}

func createCommentHandler(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err != nil || session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		postID := r.FormValue("post_id")
		content := r.FormValue("content")

		if content == "" {
			handleErr(w, nil, "Content is required", http.StatusBadRequest)
			return
		}

		_, err := db.Exec("INSERT INTO comments (post_id, user_id, content, created_at) VALUES (?, ?, ?, ?)",
			postID, session.UserID, content, time.Now())
		if err != nil {
			handleErr(w, err, "Internal server error", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/viewPost?id=%s", postID), http.StatusSeeOther)
		return
	}
}

func deletePostHandler(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err != nil || session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	postID := r.FormValue("post_id")
	if postID == "" {
		http.Error(w, "Post ID is required", http.StatusBadRequest)
		return
	}

	var userID int
	err = db.QueryRow("SELECT user_id FROM posts WHERE id = ?", postID).Scan(&userID)
	if err != nil {
		handleErr(w, err, "Post not found", http.StatusNotFound)
		return
	}

	if userID != session.UserID {
		http.Error(w, "You can only delete your own posts", http.StatusForbidden)
		return
	}

	_, err = db.Exec("UPDATE posts SET deleted = 1 WHERE id = ?", postID)
	if err != nil {
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func deleteCommentHandler(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err != nil || session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	commentID := r.FormValue("comment_id")
	if commentID == "" {
		http.Error(w, "Comment ID is required", http.StatusBadRequest)
		return
	}

	var userID, postID int
	err = db.QueryRow("SELECT user_id, post_id FROM comments WHERE id = ?", commentID).Scan(&userID, &postID)
	if err != nil {
		handleErr(w, err, "Comment not found", http.StatusNotFound)
		return
	}

	var postOwnerID int
	err = db.QueryRow("SELECT user_id FROM posts WHERE id = ?", postID).Scan(&postOwnerID)
	if err != nil {
		handleErr(w, err, "Post not found", http.StatusNotFound)
		return
	}

	if userID != session.UserID && postOwnerID != session.UserID {
		http.Error(w, "You can only delete your own comments or comments on your posts", http.StatusForbidden)
		return
	}

	_, err = db.Exec("UPDATE comments SET deleted = 1 WHERE id = ?", commentID)
	if err != nil {
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/viewPost?id=%d", postID), http.StatusSeeOther)
}

func voteHandler(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err != nil || session == nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"redirect": "/login"})
		return
	}

	postID := r.FormValue("post_id")
	commentID := r.FormValue("comment_id")
	voteTypeStr := r.FormValue("vote_type")

	voteType, err := strconv.Atoi(voteTypeStr)
	if err != nil || (voteType != 1 && voteType != -1) {
		handleErr(w, err, "Invalid vote type", http.StatusBadRequest)
		return
	}

	var existingVoteType sql.NullInt64
	var query string

	if postID != "" {
		query = "SELECT vote_type FROM votes WHERE user_id = ? AND post_id = ?"
		err = db.QueryRow(query, session.UserID, postID).Scan(&existingVoteType)
	} else if commentID != "" {
		query = "SELECT vote_type FROM votes WHERE user_id = ? AND comment_id = ?"
		err = db.QueryRow(query, session.UserID, commentID).Scan(&existingVoteType)
	}

	if err != nil && err != sql.ErrNoRows {
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	if existingVoteType.Valid {
		if existingVoteType.Int64 == int64(voteType) {
			if postID != "" {
				query = "DELETE FROM votes WHERE user_id = ? AND post_id = ?"
				_, err = db.Exec(query, session.UserID, postID)
			} else if commentID != "" {
				query = "DELETE FROM votes WHERE user_id = ? AND comment_id = ?"
				_, err = db.Exec(query, session.UserID, commentID)
			}
		} else {
			if postID != "" {
				query = "UPDATE votes SET vote_type = ? WHERE user_id = ? AND post_id = ?"
				_, err = db.Exec(query, voteType, session.UserID, postID)
			} else if commentID != "" {
				query = "UPDATE votes SET vote_type = ? WHERE user_id = ? AND comment_id = ?"
				_, err = db.Exec(query, voteType, session.UserID, commentID)
			}
		}
	} else {
		if postID != "" {
			query = "INSERT INTO votes (user_id, post_id, vote_type) VALUES (?, ?, ?)"
			_, err = db.Exec(query, session.UserID, postID, voteType)
		} else if commentID != "" {
			query = "INSERT INTO votes (user_id, comment_id, vote_type) VALUES (?, ?, ?)"
			_, err = db.Exec(query, session.UserID, commentID, voteType)
		}
	}

	if err != nil {
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Oy sayısını yeniden hesapla ve JSON olarak dön
	var likeCount, dislikeCount int
	if postID != "" {
		err = db.QueryRow(`SELECT 
			COALESCE(SUM(CASE WHEN vote_type = 1 THEN 1 ELSE 0 END), 0) AS like_count,
			COALESCE(SUM(CASE WHEN vote_type = -1 THEN 1 ELSE 0 END), 0) AS dislike_count
			FROM votes WHERE post_id = ?`, postID).Scan(&likeCount, &dislikeCount)
	} else if commentID != "" {
		err = db.QueryRow(`SELECT 
			COALESCE(SUM(CASE WHEN vote_type = 1 THEN 1 ELSE 0 END), 0) AS like_count,
			COALESCE(SUM(CASE WHEN vote_type = -1 THEN 1 ELSE 0 END), 0) AS dislike_count
			FROM votes WHERE comment_id = ?`, commentID).Scan(&likeCount, &dislikeCount)
	}

	if err != nil {
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := map[string]int{"like_count": likeCount, "dislike_count": dislikeCount}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func viewPostHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := getSession(r)

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
	var categoriesJSON string
	err := db.QueryRow(`SELECT posts.id, posts.user_id, posts.title, posts.content, posts.categories, posts.created_at, users.username,
		COALESCE(SUM(CASE WHEN votes.vote_type = 1 THEN 1 ELSE 0 END), 0) AS like_count,
		COALESCE(SUM(CASE WHEN votes.vote_type = -1 THEN 1 ELSE 0 END), 0) AS dislike_count
		FROM posts
		JOIN users ON posts.user_id = users.id
		LEFT JOIN votes ON votes.post_id = posts.id
		WHERE posts.id = ? AND posts.deleted = 0
		GROUP BY posts.id`, postID).Scan(&post.ID, &post.UserID, &post.Title, &post.Content, &categoriesJSON, &post.CreatedAt, &post.Username, &post.LikeCount, &post.DislikeCount)

	if err != nil {
		log.Println("Error querying post:", err)
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	var categories []string
	err = json.Unmarshal([]byte(categoriesJSON), &categories)
	if err != nil {
		handleErr(w, err, "Error parsing categories", http.StatusInternalServerError)
		return
	}

	post.CreatedAtFormatted = post.CreatedAt.Format("2006-01-02 15:04")
	post.Categories = categories

	rows, err := db.Query(`SELECT comments.id, comments.post_id, comments.user_id, comments.content, comments.created_at, users.username,
							COALESCE(SUM(CASE WHEN votes.vote_type = 1 THEN 1 ELSE 0 END), 0) AS like_count,
							COALESCE(SUM(CASE WHEN votes.vote_type = -1 THEN 1 ELSE 0 END), 0) AS dislike_count
							FROM comments
							JOIN users ON comments.user_id = users.id
							LEFT JOIN votes ON votes.comment_id = comments.id
							WHERE comments.post_id = ? AND comments.deleted = 0
							GROUP BY comments.id, comments.post_id, comments.user_id, comments.content, comments.created_at, users.username
							ORDER BY comments.created_at DESC`, postID)
	if err != nil {
		log.Println("Error querying comments:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var comments []Comment
	for rows.Next() {
		var comment Comment
		if err := rows.Scan(&comment.ID, &comment.PostID, &comment.UserID, &comment.Content, &comment.CreatedAt, &comment.Username, &comment.LikeCount, &comment.DislikeCount); err != nil {
			log.Println("Error scanning comment:", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		comment.CreatedAtFormatted = comment.CreatedAt.Format("2006-01-02 15:04")
		comments = append(comments, comment)
	}

	err = rows.Err()
	if err != nil {
		log.Println("Rows error:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Post     Post
		Comments []Comment
		LoggedIn bool
	}{
		Post:     post,
		Comments: comments,
		LoggedIn: session != nil,
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

func myProfileHandler(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err != nil || session == nil { // Oturum kontrolü
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Kullanıcı bilgilerini veritabanından çekme
	user, err := getUserByID(session.UserID)
	if err != nil {
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	// HTML şablonunu parse etme
	tmpl, err := template.ParseFiles("templates/myprofil.html")
	if err != nil {
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Kullanıcı bilgilerini HTML şablonuna geçirme
	err = tmpl.Execute(w, user)
	if err != nil {
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func getUserByID(userID int) (*User, error) {
	var user User
	query := "SELECT id, email, username, password FROM users WHERE id = ?"
	err := db.QueryRow(query, userID).Scan(&user.ID, &user.Email, &user.Username, &user.Password)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func sifreUnutHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/sifreunut.html")
	if err != nil {
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		handleErr(w, err, "Internal server error", http.StatusInternalServerError)
	}
}

func getFilteredPosts(searchQuery, category, sortBy string) ([]Post, error) {
    query := `SELECT posts.id, posts.user_id, posts.title, posts.content, posts.categories, posts.created_at, users.username,
                     COALESCE(SUM(CASE WHEN votes.vote_type = 1 THEN 1 ELSE 0 END), 0) AS like_count,
                     COALESCE(SUM(CASE WHEN votes.vote_type = -1 THEN 1 ELSE 0 END), 0) AS dislike_count,
                     (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id AND comments.deleted = 0) AS comment_count
              FROM posts
              JOIN users ON posts.user_id = users.id
              LEFT JOIN votes ON votes.post_id = posts.id
              WHERE posts.deleted = 0`

    args := []interface{}{} // Sorgu parametreleri için
    conditions := []string{} // Filtreleme koşulları için

    if searchQuery != "" {
        conditions = append(conditions, "(posts.title LIKE ? OR posts.content LIKE ?)")
        searchTerm := "%" + searchQuery + "%"
        args = append(args, searchTerm, searchTerm)
    }

    if category != "" {
        conditions = append(conditions, "posts.categories LIKE ?")
        categoryTerm := "%" + category + "%"
        args = append(args, categoryTerm)
    }

    if len(conditions) > 0 {
        query += " AND " + strings.Join(conditions, " AND ")
    }

    // Sıralama (varsayılan olarak oluşturulma tarihine göre azalan sıralama)
    switch sortBy {
    case "mostliked":
        query += " GROUP BY posts.id ORDER BY like_count DESC, posts.created_at DESC" // Beğeni sayısına göre sıralama
    case "mostcommented": 
        query += " GROUP BY posts.id ORDER BY comment_count DESC, posts.created_at DESC" // Yorum sayısına göre sıralama
    default:
        query += " GROUP BY posts.id ORDER BY posts.created_at DESC" // Oluşturulma tarihine göre sıralama (varsayılan)
    }

    rows, err := db.Query(query, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var posts []Post
    for rows.Next() {
        var post Post
        var categoriesJSON string
        if err := rows.Scan(&post.ID, &post.UserID, &post.Title, &post.Content, &categoriesJSON, &post.CreatedAt, &post.Username, &post.LikeCount, &post.DislikeCount, &post.CommentCount); err != nil {
            return nil, err
        }
        if err := json.Unmarshal([]byte(categoriesJSON), &post.Categories); err != nil {
            return nil, err
        }

        post.CategoriesFormatted = strings.Join(post.Categories, ", ")
        post.CreatedAtFormatted = post.CreatedAt.Format("2006-01-02 15:04")
        posts = append(posts, post)
    }
    return posts, nil
}



func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	token, err := googleOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	email, name, err := getEmailAndNameFromGoogle(token)
	if err != nil {
		http.Error(w, "Failed to get user info from Google", http.StatusInternalServerError)
		return
	}

	// Validate işlemi yapmadan önce gelen ismi uygun hale getirme
	username := strings.ToLower(strings.ReplaceAll(name, " ", "")) + "_" + generateRandomString(5) // Boşlukları kaldırma gibi bir işlem yapabilirsiniz

	userID, err := getOrCreateUser(email, username)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to save user info: %v", err), http.StatusInternalServerError)
		return
	}

	sessionToken, err := createSession(userID)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
	})

	http.Redirect(w, r, "/myprofil", http.StatusTemporaryRedirect)
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func getEmailAndNameFromGoogle(token *oauth2.Token) (string, string, error) {
	client := googleOauthConfig.Client(oauth2.NoContext, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var userInfo struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", "", err
	}

	return userInfo.Email, userInfo.Name, nil
}

func getOrCreateUser(email, username string) (int64, error) {
	var userID int64
	err := db.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&userID)
	if err == sql.ErrNoRows {
		res, err := db.Exec("INSERT INTO users (email, username) VALUES (?, ?)", email, username)
		if err != nil {
			return 0, err
		}
		userID, err = res.LastInsertId()
		if err != nil {
			return 0, err
		}
	} else if err != nil {
		return 0, err
	}
	return userID, nil
}

func createSession(userID int64) (string, error) {
	sessionToken := fmt.Sprintf("session-%d-%d", userID, time.Now().UnixNano())
	expiry := time.Now().Add(10 * time.Minute)
	_, err := db.Exec("INSERT INTO sessions (id, user_id, expiry) VALUES (?, ?, ?)", sessionToken, userID, expiry)
	if err != nil {
		return "", err
	}
	return sessionToken, nil
}

func getSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			return nil, nil // Çerez bulunamadıysa, oturum yok olarak döndür
		}
		return nil, err // Başka bir hata varsa hata döndür
	}

	sessionToken := cookie.Value

	var session Session
	err = db.QueryRow("SELECT id, user_id, expiry FROM sessions WHERE id = ?", sessionToken).Scan(&session.ID, &session.UserID, &session.Expiry)
	if err != nil {
		return nil, err
	}

	if session.Expiry.Before(time.Now()) {
		return nil, fmt.Errorf("session expired")
	}

	// Oturum açıldığında, kullanıcının diğer oturumlarını kapat
	_, err = db.Exec("DELETE FROM sessions WHERE user_id = ? AND id <> ?", session.UserID, sessionToken)
	if err != nil {
		return nil, err
	}

	// Oturum süresini her kontrol ettiğimizde uzatalım
	newExpiry := time.Now().Add(1 * time.Minute)
	_, err = db.Exec("UPDATE sessions SET expiry = ? WHERE id = ?", newExpiry, sessionToken)
	if err != nil {
		return nil, err
	}
	session.Expiry = newExpiry

	return &session, nil
}

func getMostLikedPosts(w http.ResponseWriter, r *http.Request) {
	session, _ := getSession(r)

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

    posts, err := getFilteredPosts("", "", "mostliked")
    if err != nil {
        handleErr(w, err, "Internal server error", http.StatusInternalServerError)
        return
    }
    
    tmpl, err := template.ParseFiles("templates/index.html")
    if err != nil {
        handleErr(w, err, "Internal server error", http.StatusInternalServerError)
        return
    }

    data := struct {
        Posts     []Post
        LoggedIn  bool
        SortByMostLiked bool
    }{
        Posts:     posts,
        LoggedIn:  session != nil,
        SortByMostLiked: true,
    }

    err = tmpl.Execute(w, data)
    if err != nil {
        handleErr(w, err, "Internal server error", http.StatusInternalServerError)
    }
}