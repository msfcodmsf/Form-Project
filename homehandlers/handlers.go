// homehandlers
package homehandlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"form-project/datahandlers"
	"form-project/models"
	"form-project/morehandlers"
	"form-project/utils"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/go-playground/validator"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

var (
	validate    = validator.New()
	config      Config
	registering = false // Kaydetme veya giriş yapma işlemini ayırt etmek için
)

type Config struct {
	GoogleClientID       string `json:"google_client_id"`
	GoogleClientSecret   string `json:"google_client_secret"`
	GitHubClientID       string `json:"github_client_id"`
	GitHubClientSecret   string `json:"github_client_secret"`
	FacebookClientID     string `json:"facebook_client_id"`
	FacebookClientSecret string `json:"facebook_client_secret"`
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

// OAuth 2.0 yapılandırmalarını tutmak için genel değişkenler
var googleOauthConfig *oauth2.Config // googleOauthConfig değişkeni, Google OAuth 2.0 yapılandırmasını tutar.
var githubOauthConfig *oauth2.Config
var facebookOauthConfig *oauth2.Config
var oauthStateStringGoogle string // Google OAuth durumu için
// Paket yüklenirken otomatik olarak çalışır.
func init() {
	loadConfig()
	// Google OAuth 2.0 yapılandırması oluşturulur.
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8065/google/callback",
		ClientID:     config.GoogleClientID,
		ClientSecret: config.GoogleClientSecret,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}

	githubOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8065/github/callback",
		ClientID:     config.GitHubClientID,
		ClientSecret: config.GitHubClientSecret,
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
	}

	facebookOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8065/facebook/callback",
		ClientID:     config.FacebookClientID,
		ClientSecret: config.FacebookClientSecret,
		Scopes:       []string{"email"},
		Endpoint:     facebook.Endpoint,
	}
}

// HandleGoogleLogin fonksiyonu, Google ile giriş yapmayı başlatır.
func HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	// Registerda registering değişkeni true olarak ayarlanır.
	registering = false // Kullanılma amacı giriş yapma (login) ve kaydolma (register) işlemleri arasında ayrım yapmaktır.
	oauthStateStringGoogle = generateNonce()
	url := googleOauthConfig.AuthCodeURL(oauthStateStringGoogle, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}
func generateNonce() string {
	// Rastgele 32 byte veri oluşturulur
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		// Eğer rastgele veri oluşturulurken hata alınırsa panic ile program sonlandırılır.
		panic(err)
	}
	// Oluşturulan byte slice base64 URL encoding ile string formatına dönüştürülür ve döndürülür
	return base64.URLEncoding.EncodeToString(b)
}

// HandleGoogleRegister fonksiyonu, Google ile kaydolmayı başlatır.
func HandleGoogleRegister(w http.ResponseWriter, r *http.Request) {
	registering = true
	oauthStateStringGoogle = generateNonce()
	url := googleOauthConfig.AuthCodeURL(oauthStateStringGoogle, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Ana sayfayı görüntüler.
func HomeHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := datahandlers.GetSession(r)

    searchQuery := r.URL.Query().Get("search")
    category := r.URL.Query().Get("category")
    filter := r.URL.Query().Get("filter")

    posts, err := getFilteredPosts(searchQuery, category, filter, nil)
    if err != nil {
        utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Kategorileri Getir
    categoryRows, err := datahandlers.DB.Query("SELECT name FROM categories")
    if err != nil {
        utils.HandleErr(w, err, "Kategoriler getirilirken hata oluştu.", http.StatusInternalServerError)
        return
    }
    defer categoryRows.Close()

    var categories []string
    for categoryRows.Next() {
        var category string
        if err := categoryRows.Scan(&category); err != nil {
            utils.HandleErr(w, err, "Kategori bilgileri okunurken hata oluştu.", http.StatusInternalServerError)
            return
        }
        categories = append(categories, category)
    }

    tmpl, err := template.ParseFiles("templates/index.html")
    if err != nil {
        utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
        return
    }

    data := struct {
        Posts        []models.Post
        LoggedIn     bool
        IsAdmin      bool
        IsModerator  bool
        Categories   []string // Kategoriler eklendi
    }{
        Posts:        posts,
        LoggedIn:     session != nil,
        IsAdmin:      isAdmin(r),
        IsModerator: IsModerator(r),
        Categories:   categories, // Kategoriler eklendi
    }

    err = tmpl.Execute(w, data)
    if err != nil {
        utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
    }
}

// Verilen filtrelere (arama sorgusu, kategori, filtre türü, kullanıcı ID'si) göre gönderileri veritabanından çeker.
func getFilteredPosts(searchQuery, category, filter string, userID *int) ([]models.Post, error) {
	query := `SELECT posts.id, posts.user_id, posts.title, posts.content, posts.categories, posts.created_at, users.username,
                     COALESCE(SUM(CASE WHEN votes.vote_type = 1 THEN 1 ELSE 0 END), 0) AS like_count,
                     COALESCE(SUM(CASE WHEN votes.vote_type = -1 THEN 1 ELSE 0 END), 0) AS dislike_count,
                     (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id AND comments.deleted = 0) AS comment_count
              FROM posts
              JOIN users ON posts.user_id = users.id
              LEFT JOIN votes ON votes.post_id = posts.id
              WHERE posts.deleted = 0 AND posts.moderated = 1` // Sadece onaylanmış gönderileri al

	args := []interface{}{}
	conditions := []string{}

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

	if userID != nil {
		conditions = append(conditions, "posts.user_id = ?")
		args = append(args, *userID)
	}

	if len(conditions) > 0 {
		query += " AND " + strings.Join(conditions, " AND ")
	}

	query += " GROUP BY posts.id"

	switch filter {
	case "most_liked":
		query += " ORDER BY like_count DESC"
	case "most_commented":
		query += " ORDER BY comment_count DESC"
	default:
		query += " ORDER BY posts.created_at DESC"
	}

	rows, err := datahandlers.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []models.Post
	for rows.Next() {
		var post models.Post
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

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the user is already logged in
	session, err := datahandlers.GetSession(r)
	if err == nil && session != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Check for email existence in the database (GET or POST request)
	errorMessages := make(map[string]string)
	email := r.FormValue("email")
	if email == "" {
		email = r.URL.Query().Get("email")
	}

	if email != "" {
		existingUser, _ := getUserByEmail(email)
		if existingUser != nil {
			errorMessages["Email"] = "Bu Email zaten kayıtlı."
		}
	}

	switch r.Method {
	case http.MethodPost:
		err := registerUser(w, r)
		if err != nil {
			// ... (handle other errors)

			// Pass specific error message to the template
			if err.Error() == "user already exists" {
				errorMessages["Email"] = "Bu Email zaten kayıtlı."
			} else if err.Error() == "username already exists" {
				errorMessages["Username"] = "Bu kullanıcı adı zaten alınmış."
			} else {
				errorMessages["Email"] = err.Error() // Generic error message
			}

			renderRegisterTemplate(w, models.RegisterTemplateData{ErrorMessages: errorMessages})
			return
		}
	default: // GET request
		tmpl, err := template.ParseFiles("templates/register.html")
		if err != nil {

			return
		}

		// Şablon verilerini hazırla
		data := models.RegisterTemplateData{
			ErrorMessages: errorMessages, // Hata mesajlarını şablona aktar
			Email:         email,
		}
		err = tmpl.Execute(w, data)
		if err != nil {
			utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		}
	}
}

func registerUser(w http.ResponseWriter, r *http.Request) error {
	email := r.FormValue("email")
	googleOAuth := r.FormValue("google_oauth")

	// 1. Check if email exists (regardless of registration method)
	var existingUserID int
	err := datahandlers.DB.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&existingUserID)
	utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)

	existingUser, _ := getUserByEmail(email)
	if existingUser != nil {
		return fmt.Errorf("user already exists")
	}

	var user models.User
	if googleOAuth == "true" {
		// 2b. Google OAuth (New Registration)
		code := r.FormValue("code")
		token, err := googleOauthConfig.Exchange(r.Context(), code)
		if err != nil {
			return err
		}

		email, name, err := getEmailAndNameFromGoogle(token)
		if err != nil {
			return err
		}

		username := strings.ToLower(strings.ReplaceAll(name, " ", "")) + "_" + generateRandomString(5)

		user = models.User{
			Email:    email,
			Username: sql.NullString{String: username, Valid: true},
			Password: sql.NullString{Valid: false}, // No password for Google OAuth
		}
	} else { // Normal registration
		// 2d. Normal Registration (New Account)
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Username check
		var count int
		err := datahandlers.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
		if err != nil {
			return err
		}
		if count > 0 {
			registerError(w, r, "username already exists")
			return fmt.Errorf("username already exists")
		}

		// Password validation
		if err := validate.Var(password, "required,min=6"); err != nil {
			return err
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}

		user = models.User{
			Email:    email,
			Username: sql.NullString{String: username, Valid: true},
			Password: sql.NullString{String: string(hashedPassword), Valid: true},
		}
	}

	// 3. Save the user
	err = saveUser(&user)
	if err != nil {
		return err
	}

	// 4. Create session and redirect
	sessionToken, err := createSession(int64(user.ID))
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // If using HTTPS
	})

	http.Redirect(w, r, "/myprofil", http.StatusSeeOther) // Redirect to profile page on successful registration

	return nil // Successful registration
}

func registerError(w http.ResponseWriter, r *http.Request, s string) {
	panic("unimplemented")
}

func saveUser(user *models.User) error {
	_, err := datahandlers.DB.Exec("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", user.Email, user.Username, user.Password)
	return err
}

func getUserByEmail(email string) (*models.User, error) {
	var user models.User
	err := datahandlers.DB.QueryRow("SELECT id, email, username, password FROM users WHERE email = ?", email).Scan(&user.ID, &user.Email, &user.Username, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // User not found
		}
		return nil, err // Database error
	}
	return &user, nil
}

func getGoogleUserByEmail(email string) (int64, error) {
	var userID int64
	// Check for null password (indicating Google registration)
	err := datahandlers.DB.QueryRow("SELECT id FROM users WHERE email = ? AND password IS NULL", email).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil // User not found
		}
		return 0, err // Database error
	}
	return userID, nil
}

// Kayıt formunu göstermek için HTML şablonunu render eder.
func renderRegisterTemplate(w http.ResponseWriter, data models.RegisterTemplateData) {
	tmpl, err := template.ParseFiles("templates/register.html")
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
	}
}

// Kullanıcı oturum açma işlemini işler.
// Kullanıcı oturum açma işlemini işler.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Kullanıcı zaten giriş yapmış mı kontrol et
	session, err := datahandlers.GetSession(r)
	if err == nil && session != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Hata mesajını taşımak için bir yapı oluşturun
	tmplData := struct {
		Error string
	}{}

	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")
		googleOAuth := r.FormValue("google_oauth")

		if googleOAuth == "true" {
			// Google OAuth ile giriş yapma işlemleri
			code := r.FormValue("code")
			token, err := googleOauthConfig.Exchange(r.Context(), code)
			if err != nil {
				http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
				return
			}

			email, _, err := getEmailAndNameFromGoogle(token)
			if err != nil {
				http.Error(w, "Failed to get user info from Google", http.StatusInternalServerError)
				return
			}

			// Google ile kayıtlı kullanıcıyı bul
			userID, err := getGoogleUserByEmail(email)
			if err != nil {
				if err == sql.ErrNoRows {
					utils.HandleErr(w, err, "User not found. Please register first.", http.StatusUnauthorized)
					return
				}
				utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
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

			http.Redirect(w, r, "/myprofil", http.StatusSeeOther)
			return

		} else {
			// Normal giriş yapma işlemleri
			var id int
			var hashedPassword string
			err := datahandlers.DB.QueryRow("SELECT id, password FROM users WHERE email = ?", email).Scan(&id, &hashedPassword)
			if err != nil {
				if err == sql.ErrNoRows {
					tmplData.Error = "Geçersiz e-posta veya şifre" // Hata mesajını tmplData'ya atayın
				} else {
					utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
				}
				return
			}
			err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
			if err != nil {
				tmplData.Error = "Geçersiz e-posta veya şifre" // Hata mesajını tmplData'ya atayın
				return
			}

			sessionToken := uuid.New().String()
			expiresAt := time.Now().Add(10 * time.Minute)

			_, err = datahandlers.DB.Exec("INSERT INTO sessions (id, user_id, expiry) VALUES (?, ?, ?)", sessionToken, id, expiresAt)
			if err != nil {
				utils.HandleErr(w, err, "Session creation failed", http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:     "session_token",
				Value:    sessionToken,
				Expires:  expiresAt,
				HttpOnly: true,
				Secure:   true,
			})

			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}

	// Query parametrelerinden hata mesajını al
	if errorMessage := r.URL.Query().Get("error"); errorMessage != "" {
		tmplData.Error = errorMessage
	}

	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Hata mesajını şablona geçirerek render et
	err = tmpl.Execute(w, tmplData)
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
	}
}

// Kullanıcının oturumunu kapatır.
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	sessionToken := cookie.Value
	_, err = datahandlers.DB.Exec("DELETE FROM sessions WHERE id = ?", sessionToken)
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Now().Add(-1 * time.Second),
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func HandleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	// GitHub OAuth 2.0 URL'sini oluştur ve kullanıcıyı yönlendirir
	registering = false
	oauthStateStringGoogle = generateNonce()
	url := googleOauthConfig.AuthCodeURL(oauthStateStringGoogle, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// GitHub callback işlemini gerçekleştirir
func HandleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	token, err := githubOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	email, name, err := getEmailAndNameFromGitHub(token)
	if err != nil {
		http.Error(w, "Failed to get user info from GitHub", http.StatusInternalServerError)
		return
	}
	// Kullanıcı adını oluştur ve kullanıcıyı kaydet veya mevcut kullanıcıyı getir
	username := strings.ToLower(strings.ReplaceAll(name, " ", "")) + "_" + generateRandomString(5)

	if registering {
		// Kayıt işlemi
		user, _ := getUserByEmail(email)
		if user != nil {
			tmpl, err := template.ParseFiles("templates/register.html")
			if err != nil {
				utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
				return
			}

			data := models.RegisterTemplateData{Email: email}
			data.ErrorMessages = map[string]string{"Email": "Bu Email zaten kayıtlı."}

			// Şablonu işleyerek yanıtı gönder
			err = tmpl.Execute(w, data)
			if err != nil {
				utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
			}
		} else {
			userId, _ := getOrCreateUser(email, username)

			sessionToken, _ := createSession(userId)

			http.SetCookie(w, &http.Cookie{
				Name:     "session_token",
				Value:    sessionToken,
				Path:     "/",
				HttpOnly: true,
			})
			// Kayıt başarılı, kullanıcıyı profil sayfasına yönlendir
			http.Redirect(w, r, "/myprofil", http.StatusTemporaryRedirect)
		}

	} else {
		// Oturum açma işlemi

		// Kullanıcıyı e-posta ile veritabanında bul
		var userID int
		err = datahandlers.DB.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&userID)
		if err != nil {
			if err == sql.ErrNoRows {
				// Kullanıcı bulunamadı, hata mesajı göster
				utils.HandleErr(w, err, "Kullanıcı bulunamadı. Lütfen önce kaydolun.", http.StatusUnauthorized)
			} else {
				// Veritabanı hatası
				utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
			}
			return
		}

		// Oturum oluştur
		sessionToken, err := createSession(int64(userID))
		if err != nil {
			http.Error(w, "Oturum oluşturulamadı.", http.StatusInternalServerError)
			return
		}

		// Tarayıcıya oturum çerezi gönder
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Path:     "/",
			HttpOnly: true,
		})

		// Oturum açma başarılı, kullanıcıyı ana sayfaya yönlendir
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// GitHub access token'ı kullanarak kullanıcı bilgilerini alır
func getEmailAndNameFromGitHub(token *oauth2.Token) (string, string, error) {
	client := githubOauthConfig.Client(oauth2.NoContext, token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	// GitHub API'sinden dönen JSON'ı ayrıştır
	var userInfo struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", "", err
	}

	// GitHub email adresini ayrı bir endpoint'den almak gerekiyor.
	if userInfo.Email == "" {
		emailResp, err := client.Get("https://api.github.com/user/emails")
		if err != nil {
			return "", "", err
		}
		defer emailResp.Body.Close()

		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := json.NewDecoder(emailResp.Body).Decode(&emails); err != nil {
			return "", "", err
		}
		for _, e := range emails {
			if e.Primary && e.Verified {
				userInfo.Email = e.Email
				break
			}
		}
	}

	return userInfo.Email, userInfo.Name, nil
}

// HandleGoogleCallback fonksiyonu, Google'dan gelen callback isteğini işler.
func HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	// CSRF (Çapraz Site İstek Sahteciliği) koruması
	if r.FormValue("state") != oauthStateStringGoogle {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	// Google'dan dönen yetkilendirme kodunu al
	code := r.URL.Query().Get("code")

	// Yetkilendirme kodunu access token ile değiştir
	token, err := googleOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Token değişimi başarısız oldu.", http.StatusInternalServerError)
		return
	}

	// Access token ile Google'dan kullanıcı bilgilerini al
	email, name, err := getEmailAndNameFromGoogle(token)
	if err != nil {
		http.Error(w, "Google'dan kullanıcı bilgileri alınamadı.", http.StatusInternalServerError)
		return
	}

	// Kullanıcı adını oluştur (boşlukları kaldır ve küçük harfe çevir)
	username := strings.ToLower(strings.ReplaceAll(name, " ", ""))

	if registering {
		// Kayıt işlemi
		user, _ := getUserByEmail(email)
		if user != nil {
			tmpl, err := template.ParseFiles("templates/register.html")
			if err != nil {
				utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
				return
			}

			data := models.RegisterTemplateData{Email: email}
			data.ErrorMessages = map[string]string{"Email": "Bu Email zaten kayıtlı."}

			// Şablonu işleyerek yanıtı gönder
			err = tmpl.Execute(w, data)
			if err != nil {
				utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
			}
		} else {
			userId, _ := getOrCreateUser(email, username)

			sessionToken, _ := createSession(userId)

			http.SetCookie(w, &http.Cookie{
				Name:     "session_token",
				Value:    sessionToken,
				Path:     "/",
				HttpOnly: true,
			})
			// Kayıt başarılı, kullanıcıyı profil sayfasına yönlendir
			http.Redirect(w, r, "/myprofil", http.StatusTemporaryRedirect)
		}

	} else {
		// Oturum açma işlemi

		// Kullanıcıyı e-posta ile veritabanında bul
		var userID int
		err = datahandlers.DB.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&userID)
		if err != nil {
			if err == sql.ErrNoRows {
				// Kullanıcı bulunamadı, hata mesajı göster
				utils.HandleErr(w, err, "Kullanıcı bulunamadı. Lütfen önce kaydolun.", http.StatusUnauthorized)
			} else {
				// Veritabanı hatası
				utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
			}
			return
		}

		// Oturum oluştur
		sessionToken, err := createSession(int64(userID))
		if err != nil {
			http.Error(w, "Oturum oluşturulamadı.", http.StatusInternalServerError)
			return
		}

		// Tarayıcıya oturum çerezi gönder
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Path:     "/",
			HttpOnly: true,
		})

		// Oturum açma başarılı, kullanıcıyı ana sayfaya yönlendir
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
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

// getOrCreateUser fonksiyonu, e-posta adresine göre kullanıcıyı bulur veya yeni bir kullanıcı oluşturur.
func getOrCreateUser(email, username string) (int64, error) {
	var userID int64
	err := datahandlers.DB.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&userID)

	if err != nil {
		if err == sql.ErrNoRows {
			// If user doesn't exist, create a new one
			res, err := datahandlers.DB.Exec("INSERT INTO users (email, username) VALUES (?, ?)", email, username)
			if err != nil {
				return 0, err
			}
			userID, err = res.LastInsertId()
			if err != nil {
				return 0, err
			}
		} else {
			// Other database errors
			return 0, err
		}
	}

	return userID, nil
}

// createSession fonksiyonu, kullanıcı için yeni bir oturum oluşturur.
func createSession(userID int64) (string, error) {
	sessionToken := fmt.Sprintf("session-%d-%d", userID, time.Now().UnixNano())
	expiry := time.Now().Add(10 * time.Minute)
	_, err := datahandlers.DB.Exec("INSERT INTO sessions (id, user_id, expiry) VALUES (?, ?, ?)", sessionToken, userID, expiry)
	if err != nil {
		return "", err
	}
	return sessionToken, nil
}

func SifreUnutHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/sifreunut.html")
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
	}
}

func HandleFacebookLogin(w http.ResponseWriter, r *http.Request) {
	url := facebookOauthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func HandleFacebookCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	token, err := facebookOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	email, name, err := getEmailAndNameFromFacebook(token)
	if err != nil {
		http.Error(w, "Failed to get user info from Facebook", http.StatusInternalServerError)
		return
	}

	username := strings.ToLower(strings.ReplaceAll(name, " ", "")) + "_" + generateRandomString(5)

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

// Facebook profilinden e-posta adresini ve adını alır.
func getEmailAndNameFromFacebook(token *oauth2.Token) (string, string, error) {
	client := facebookOauthConfig.Client(oauth2.NoContext, token)
	resp, err := client.Get("https://graph.facebook.com/me?fields=id,name,email")
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

const maxUploadSize = 20 * 1024 * 1024 // 20 MB

func UploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		http.Error(w, "The uploaded file is too big. Please choose an file that's less than 20MB in size", http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Dosya tipi kontrolü
	allowedExtensions := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
	}
	ext := filepath.Ext(handler.Filename)
	if !allowedExtensions[ext] {
		http.Error(w, "The provided file format is not allowed. Please upload a JPEG, PNG, or GIF image", http.StatusBadRequest)
		return
	}

	// Dosyayı kaydet
	f, err := os.OpenFile("./uploads/"+handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		http.Error(w, "Internal Server Error: Dosya kaydedilemedi.", http.StatusInternalServerError)
		log.Println("Error saving file:", err) // Loglara hata mesajını yaz
		return
	}
	defer f.Close()
	io.Copy(f, file)

	fmt.Fprintf(w, "File uploaded successfully: %s", handler.Filename)
}

func isAdmin(r *http.Request) bool {
	session, _ := datahandlers.GetSession(r)
	if session != nil {
		user, err := morehandlers.GetUserByID(session.UserID)
		if err != nil {
			return false
		}
		return user.Role == "admin"
	}
	return false
}

func CheckAdminStatusHandler(w http.ResponseWriter, r *http.Request) {
	// Gelen isteğin POST olup olmadığını kontrol et
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// JSON verisini oku
	var requestData struct {
		SessionToken string `json:"sessionToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		utils.HandleErr(w, err, "Invalid request data", http.StatusBadRequest)
		return
	}

	// Session'ı doğrula (datahandlers.GetSession fonksiyonunu kullanabilirsiniz)
	session, err := datahandlers.GetSessionFromToken(requestData.SessionToken)
	if err != nil || session == nil { // Oturum bulunamazsa veya hata oluşursa
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Kullanıcının admin olup olmadığını kontrol et
	user, err := morehandlers.GetUserByID(session.UserID)
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	isAdmin := user.Role == "admin"
	response := map[string]bool{"isAdmin": isAdmin}
	json.NewEncoder(w).Encode(response)
}

func AdminPanelHandler(w http.ResponseWriter, r *http.Request) {
    // 1. Yönetici Oturum Kontrolü
    session, err := datahandlers.GetSession(r)
    if err != nil || session == nil {
        http.Error(w, "Yetkisiz Erişim", http.StatusUnauthorized)
        return
    }

    // 2. Yönetici Yetki Kontrolü
    adminUser, err := morehandlers.GetUserByID(session.UserID)
    if err != nil || adminUser.Role != "admin" {
        http.Error(w, "Bu Sayfaya Erişim Yetkiniz Yok", http.StatusForbidden)
        return
    }

    // 3. Kullanıcıları Getir (Yöneticiler hariç)
    userRows, err := datahandlers.DB.Query("SELECT id, username, email, role FROM users WHERE role != 'admin'")
    if err != nil {
        utils.HandleErr(w, err, "Kullanıcılar getirilirken hata oluştu.", http.StatusInternalServerError)
        return
    }
    defer userRows.Close()

    var users []models.User
    for userRows.Next() {
        var user models.User
        if err := userRows.Scan(&user.ID, &user.Username, &user.Email, &user.Role); err != nil {
            utils.HandleErr(w, err, "Kullanıcı bilgileri okunurken hata oluştu.", http.StatusInternalServerError)
            return
        }
        users = append(users, user)
    }

    // 4. Moderatörlük İsteklerini Getir
    requestRows, err := datahandlers.DB.Query("SELECT user_id, reason FROM moderator_requests")
    if err != nil {
        utils.HandleErr(w, err, "Moderatör istekleri getirilirken hata oluştu.", http.StatusInternalServerError)
        return
    }
    defer requestRows.Close()

    var moderatorRequests []models.ModeratorRequest
    for requestRows.Next() {
        var request models.ModeratorRequest
        if err := requestRows.Scan(&request.UserID, &request.Reason); err != nil {
            utils.HandleErr(w, err, "Moderatör isteği bilgileri okunurken hata oluştu.", http.StatusInternalServerError)
            return
        }

        request.Username, err = getUserNameByID(request.UserID)
        if err != nil {
            utils.HandleErr(w, err, "Kullanıcı adı getirilirken hata oluştu.", http.StatusInternalServerError)
            return
        }
        moderatorRequests = append(moderatorRequests, request)
    }

    // 5. Raporları Getir
    reportRows, err := datahandlers.DB.Query("SELECT id, post_id, moderator_id, reason, status FROM reports WHERE post_id IN (SELECT id FROM posts WHERE deleted = 0)")
    if err != nil {
        utils.HandleErr(w, err, "Raporlar getirilirken hata oluştu.", http.StatusInternalServerError)
        return
    }
    defer reportRows.Close()

    var reports []models.Report
    for reportRows.Next() {
        var report models.Report
        if err := reportRows.Scan(&report.ID, &report.PostID, &report.ModeratorID, &report.Reason, &report.Status); err != nil {
            utils.HandleErr(w, err, "Rapor bilgileri okunurken hata oluştu.", http.StatusInternalServerError)
            return
        }

        report.PostTitle, err = getPostTitleByID(report.PostID)
        if err != nil {
            utils.HandleErr(w, err, "Gönderi başlığı getirilirken hata oluştu.", http.StatusInternalServerError)
            return
        }
        report.ModeratorName, err = getUserNameByID(report.ModeratorID)
        if err != nil {
            utils.HandleErr(w, err, "Moderatör adı getirilirken hata oluştu.", http.StatusInternalServerError)
            return
        }

        reports = append(reports, report)
    }

    // 6. Kategorileri Getir
    categoryRows, err := datahandlers.DB.Query("SELECT name FROM categories")
    if err != nil {
        utils.HandleErr(w, err, "Kategoriler getirilirken hata oluştu.", http.StatusInternalServerError)
        return
    }
    defer categoryRows.Close()

    var categories []string
    for categoryRows.Next() {
        var category string
        if err := categoryRows.Scan(&category); err != nil {
            utils.HandleErr(w, err, "Kategori bilgileri okunurken hata oluştu.", http.StatusInternalServerError)
            return
        }
        categories = append(categories, category)
    }

    // 7. Şablon Verilerini Hazırla
    data := struct {
        Users             []models.User
        AdminUser         *models.User
        ModeratorRequests []models.ModeratorRequest
        Reports           []models.Report
        Categories        []string
    }{
        Users:             users,
        AdminUser:         adminUser,
        ModeratorRequests: moderatorRequests,
        Reports:           reports,
        Categories:        categories,
    }

    // 8. Şablonu İşle ve Gönder
    tmpl, err := template.ParseFiles("templates/admin.html")
    if err != nil {
        utils.HandleErr(w, err, "Şablon ayrıştırılırken hata oluştu.", http.StatusInternalServerError)
        return
    }
    err = tmpl.Execute(w, data)
    if err != nil {
        utils.HandleErr(w, err, "Şablon işlenirken hata oluştu.", http.StatusInternalServerError)
    }
}
func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	// Yetkilendirme kontrolü:
	if !isAdmin(r) {
		http.Error(w, "Forbidden", http.StatusForbidden) // Yetkisiz kullanıcıları engelle
		return
	}

	userID := r.FormValue("user_id")

	// Kullanıcı ID'sinin geçerli olup olmadığını kontrol edin
	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	// Kullanıcıyı veritabanından silme işlemi
	_, err := datahandlers.DB.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		utils.HandleErr(w, err, "Error deleting user", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther) // Admin paneline geri yönlendir
}

func UpdateUserRoleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, err := datahandlers.GetSession(r)
	if err != nil || session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	adminUser, err := morehandlers.GetUserByID(session.UserID)
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	if adminUser.Role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	userID := r.FormValue("user_id")
	role := r.FormValue("role")

	_, err = datahandlers.DB.Exec("UPDATE users SET role = ? WHERE id = ?", role, userID)
	if err != nil {
		utils.HandleErr(w, err, "Error updating user role", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func IsModerator(r *http.Request) bool {
	session, _ := datahandlers.GetSession(r)
	if session != nil {
		user, err := morehandlers.GetUserByID(session.UserID)
		if err != nil {
			return false
		}
		return user.Role == "moderator" // Check for moderator role
	}
	return false
}

func ModeratorPanelHandler(w http.ResponseWriter, r *http.Request) {
	session, err := datahandlers.GetSession(r)
	if err != nil || session == nil {
		http.Error(w, "Yetkisiz Erişim", http.StatusUnauthorized)
		return
	}

	// Moderatör kullanıcı bilgilerini al (gerekirse bu kısmı düzenlemeniz gerekebilir)
	moderatorUser, err := morehandlers.GetUserByID(session.UserID)
	if err != nil {
		utils.HandleErr(w, err, "Sunucu Hatası", http.StatusInternalServerError)
		return
	}

	if moderatorUser.Role != "moderator" { // Kullanıcının moderatör olup olmadığını kontrol et
		http.Error(w, "Bu Sayfaya Erişim Yetkiniz Yok", http.StatusForbidden)
		return
	}

	// Moderasyon gerektiren gönderileri al (örneğin, rapor edilmiş gönderiler, onay bekleyen gönderiler)
	// Burayı veritabanınızdaki verilere göre düzenlemelisiniz
	postsToModerate, err := getPostsToModerate()
	if err != nil {
		utils.HandleErr(w, err, "Sunucu Hatası", http.StatusInternalServerError)
		return
	}

	// Şablon için verileri hazırla
	data := struct {
		ModeratorUser   *models.User
		PostsToModerate []models.Post // Post yapısının olduğunu varsayıyoruz
	}{
		ModeratorUser:   moderatorUser,
		PostsToModerate: postsToModerate,
	}

	// Moderatör panel şablonunu ayrıştır ve çalıştır
	tmpl, err := template.ParseFiles("templates/moderatör.html")
	if err != nil {
		utils.HandleErr(w, err, "Sunucu Hatası", http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		utils.HandleErr(w, err, "Sunucu Hatası", http.StatusInternalServerError)
	}
}

// In your homehandlers.go file:

func getPostsToModerate() ([]models.Post, error) {
	var posts []models.Post

	// SQL sorgusu: moderated = 0 olan ve silinmemiş gönderileri seçer.
	rows, err := datahandlers.DB.Query(`
        SELECT p.id, p.user_id, p.title, p.content, p.categories, p.created_at, u.username
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.moderated = 0 AND p.deleted = 0
    `)

	if err != nil {
		log.Println("Moderasyon gerektiren gönderileri alma hatası:", err)
		return nil, err // Hata durumunda nil ve hata mesajı döndürülür.
	}
	defer rows.Close()

	// Sorgu sonuçlarını Post struct'larına dönüştürme
	for rows.Next() {
		var post models.Post
		var categoriesJSON string

		// Sütun değerlerini post değişkenine aktar
		if err := rows.Scan(&post.ID, &post.UserID, &post.Title, &post.Content, &categoriesJSON, &post.CreatedAt, &post.Username); err != nil {
			return nil, err
		}

		// JSON formatındaki kategorileri ayrıştır
		if err := json.Unmarshal([]byte(categoriesJSON), &post.Categories); err != nil {
			return nil, err
		}

		// Kategorileri virgülle ayırarak formatla
		post.CategoriesFormatted = strings.Join(post.Categories, ", ")
		post.CreatedAtFormatted = post.CreatedAt.Format("2006-01-02 15:04")
		posts = append(posts, post) // Oluşturulan post'u posts listesine ekle
	}

	return posts, nil // Moderasyon bekleyen gönderi listesini döndür
}

// In your homehandlers.go file:

func OnaylaHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Moderatör Kontrolü
	if !IsModerator(r) {
		http.Error(w, "Bu sayfaya erişim yetkiniz yok.", http.StatusForbidden)
		return
	}

	// 2. Gönderi ID'sini Al
	postID := r.FormValue("post_id")
	if postID == "" {
		http.Error(w, "Geçersiz gönderi ID'si.", http.StatusBadRequest)
		return
	}

	// 3. Gönderiyi Onayla (Veritabanı Güncellemesi)
	_, err := datahandlers.DB.Exec("UPDATE posts SET moderated = 1 WHERE id = ?", postID)
	if err != nil {
		utils.HandleErr(w, err, "Gönderi onaylanırken hata oluştu.", http.StatusInternalServerError)
		return
	}

	// 4. Yönlendirme (Moderatör Paneline Geri)
	http.Redirect(w, r, "/moderatör", http.StatusSeeOther)
}

func ReddetHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Moderatör Kontrolü
	if !IsModerator(r) {
		http.Error(w, "Bu sayfaya erişim yetkiniz yok.", http.StatusForbidden)
		return
	}

	// 2. Gönderi ID'sini Al
	postID := r.FormValue("post_id")
	if postID == "" {
		http.Error(w, "Geçersiz gönderi ID'si.", http.StatusBadRequest)
		return
	}

	// 3. Gönderiyi Reddet (Veritabanından Sil)
	_, err := datahandlers.DB.Exec("DELETE FROM posts WHERE id = ?", postID)
	if err != nil {
		utils.HandleErr(w, err, "Gönderi reddedilirken hata oluştu.", http.StatusInternalServerError)
		return
	}

	// 4. Yönlendirme (Moderatör Paneline Geri)
	http.Redirect(w, r, "/moderatör", http.StatusSeeOther)
}

// homehandlers.go içinde
func HandleModeratorRequest(w http.ResponseWriter, r *http.Request) {
	// 1. Oturum Kontrolü
	session, err := datahandlers.GetSession(r)
	if err != nil || session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// 2. Form Gönderimi Kontrolü
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 3. Başvuru Nedenini Al
	reason := r.FormValue("reason") // Başvuru nedeni için form alanı

	// 4. Veritabanına Başvuruyu Kaydet
	_, err = datahandlers.DB.Exec("INSERT INTO moderator_requests (user_id, reason) VALUES (?, ?)", session.UserID, reason)
	if err != nil {
		utils.HandleErr(w, err, "Başvuru kaydedilirken hata oluştu", http.StatusInternalServerError)
		return
	}

	// 5. Başarılı Mesajı ve Yönlendirme
	// Başarılı başvuru mesajı gösterilebilir veya doğrudan yönlendirme yapılabilir.
	http.Redirect(w, r, "/basarili-basvuru", http.StatusSeeOther)
}

func getUserNameByID(userID int) (string, error) {
	var username string
	err := datahandlers.DB.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)
	return username, err
}

// homehandlers.go içerisinde
// ... (diğer fonksiyonlar)

func ApproveModeratorRequestHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Yönetici Kontrolü
	if !isAdmin(r) {
		http.Error(w, "Bu sayfaya erişim yetkiniz yok.", http.StatusForbidden)
		return
	}

	// 2. Kullanıcı ID'sini Al
	userID := r.FormValue("user_id")
	if userID == "" {
		http.Error(w, "Geçersiz kullanıcı ID'si.", http.StatusBadRequest)
		return
	}

	// 3. Kullanıcının Rolünü Güncelle
	_, err := datahandlers.DB.Exec("UPDATE users SET role = 'moderator' WHERE id = ?", userID)
	if err != nil {
		utils.HandleErr(w, err, "Kullanıcının rolü güncellenirken hata oluştu.", http.StatusInternalServerError)
		return
	}

	// 4. İsteği Sil
	_, err = datahandlers.DB.Exec("DELETE FROM moderator_requests WHERE user_id = ?", userID)
	if err != nil {
		utils.HandleErr(w, err, "Moderatör isteği silinirken hata oluştu.", http.StatusInternalServerError)
		return
	}

	// 5. Yönlendirme (Admin Paneline Geri)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func RejectModeratorRequestHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Yönetici Kontrolü
	if !isAdmin(r) {
		http.Error(w, "Bu sayfaya erişim yetkiniz yok.", http.StatusForbidden)
		return
	}

	// 2. Kullanıcı ID'sini Al
	userID := r.FormValue("user_id")
	if userID == "" {
		http.Error(w, "Geçersiz kullanıcı ID'si.", http.StatusBadRequest)
		return
	}

	// 3. İsteği Sil
	_, err := datahandlers.DB.Exec("DELETE FROM moderator_requests WHERE user_id = ?", userID)
	if err != nil {
		utils.HandleErr(w, err, "Moderatör isteği silinirken hata oluştu.", http.StatusInternalServerError)
		return
	}

	// 4. Yönlendirme (Admin Paneline Geri)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func ApproveReportHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Yönetici Oturum Kontrolü
	session, err := datahandlers.GetSession(r)
	if err != nil || session == nil || !isAdmin(r) {
		http.Error(w, "Yetkisiz Erişim", http.StatusUnauthorized)
		return
	}

	// 2. Rapor ID'sini Al
	reportIDStr := r.FormValue("report_id")
	reportID, err := strconv.Atoi(reportIDStr)
	if err != nil {
		http.Error(w, "Geçersiz rapor ID'si.", http.StatusBadRequest)
		return
	}

	// 3. Raporu Onayla ve İlgili Gönderiyi Sil
	tx, err := datahandlers.DB.Begin()
	if err != nil {
		utils.HandleErr(w, err, "Veritabanı işlemi başlatılamadı.", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	_, err = tx.Exec("UPDATE reports SET status = 'approved' WHERE id = ?", reportID)
	if err != nil {
		utils.HandleErr(w, err, "Rapor onaylanırken hata oluştu.", http.StatusInternalServerError)
		return
	}

	var postID int
	err = tx.QueryRow("SELECT post_id FROM reports WHERE id = ?", reportID).Scan(&postID)
	if err != nil {
		utils.HandleErr(w, err, "Rapor edilen gönderi bulunamadı.", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec("DELETE FROM posts WHERE id = ?", postID)
	if err != nil {
		utils.HandleErr(w, err, "Gönderi silinirken hata oluştu.", http.StatusInternalServerError)
		return
	}

	err = tx.Commit()
	if err != nil {
		utils.HandleErr(w, err, "Veritabanı işlemi tamamlanamadı.", http.StatusInternalServerError)
		return
	}

	// 4. Yönlendirme (Admin Paneline Geri)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func ReportPostHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Oturum ve Moderatör Kontrolü
	session, err := datahandlers.GetSession(r)
	if err != nil || session == nil || !IsModerator(r) {
		http.Error(w, "Yetkisiz Erişim", http.StatusUnauthorized)
		return
	}

	// 2. Form Verilerini Al (post_id, reason)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	postIDStr := r.FormValue("post_id")
	postID, err := strconv.Atoi(postIDStr)
	if err != nil {
		http.Error(w, "Geçersiz gönderi ID'si", http.StatusBadRequest)
		return
	}

	// (Rapor nedeni isteğe bağlı olarak alınabilir)
	reason := r.FormValue("reason")

	// 3. Veritabanına Raporu Kaydet
	_, err = datahandlers.DB.Exec(
		"INSERT INTO reports (post_id, moderator_id, reason, status) VALUES (?, ?, ?, 'pending')", // status eklendi
		postID, session.UserID, reason,
	)
	

	if err != nil {
		utils.HandleErr(w, err, "Rapor kaydedilirken hata oluştu", http.StatusInternalServerError)
		return
	}

	// 4. Yönlendirme (Moderatör Paneline veya Başarılı Mesaj)
	http.Redirect(w, r, "/moderatör", http.StatusSeeOther)
}

func getPostTitleByID(postID int) (string, error) {
    var title string
    err := datahandlers.DB.QueryRow("SELECT title FROM posts WHERE id = ? AND deleted = 0", postID).Scan(&title) // Silinmemiş gönderileri kontrol et
    if err != nil {
        if err == sql.ErrNoRows {
            return "", fmt.Errorf("Gönderi bulunamadı veya silinmiş olabilir (ID: %d)", postID)
        }
        return "", err
    }
    return title, nil
}


func RejectReportHandler(w http.ResponseWriter, r *http.Request) {
    // 1. Yönetici Oturum Kontrolü
    session, err := datahandlers.GetSession(r)
    if err != nil || session == nil || !isAdmin(r) {
        http.Error(w, "Yetkisiz Erişim", http.StatusUnauthorized)
        return
    }

    // 2. Rapor ID'sini Al
    reportIDStr := r.FormValue("report_id")
    reportID, err := strconv.Atoi(reportIDStr)
    if err != nil {
        http.Error(w, "Geçersiz rapor ID'si.", http.StatusBadRequest)
        return
    }

    // 3. Raporu Reddet (Veritabanında Güncelle)
    _, err = datahandlers.DB.Exec("UPDATE reports SET status = 'rejected' WHERE id = ?", reportID)
    if err != nil {
        utils.HandleErr(w, err, "Rapor reddedilirken hata oluştu.", http.StatusInternalServerError)
        return
    }

    // 4. Yönlendirme (Admin Paneline Geri)
    http.Redirect(w, r, "/admin", http.StatusSeeOther)
}


// Kategori ekleme işlemi
// Kategori ekleme işlemi
func AddCategoryHandler(w http.ResponseWriter, r *http.Request) {
    // 1. Yöntem Kontrolü
    if r.Method != http.MethodPost {
        http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
        return
    }

    // 2. Yönetici Yetkilendirme Kontrolü
    session, err := datahandlers.GetSession(r)
    if err != nil || session == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    if !isAdmin(r) {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    // 3. Formdan Kategori Adını Al
    categoryName := strings.TrimSpace(r.FormValue("categoryName")) // Boşlukları temizle
    if categoryName == "" {
        http.Error(w, "Kategori adı boş olamaz", http.StatusBadRequest)
        return
    }

    // 4. Veritabanına Ekle (Transaction ile)
    tx, err := datahandlers.DB.Begin()
    if err != nil {
        utils.HandleErr(w, err, "Veritabanı işlemi başlatılamadı", http.StatusInternalServerError)
        return
    }
    defer tx.Rollback() // Hata durumunda işlemi geri al

    _, err = tx.Exec("INSERT INTO categories (name) VALUES (?)", categoryName)
    if err != nil {
        tx.Rollback() // Hata durumunda işlemi geri al
        // Hata kontrolü: Eğer kategori zaten varsa özel bir hata mesajı döndür
        if strings.Contains(err.Error(), "UNIQUE constraint failed") {
            http.Error(w, "Bu kategori zaten mevcut", http.StatusBadRequest)
        } else {
            utils.HandleErr(w, err, "Kategori eklenirken hata oluştu", http.StatusInternalServerError)
        }
        return
    }

    err = tx.Commit() // İşlemi onayla
    if err != nil {
        utils.HandleErr(w, err, "Veritabanı işlemi tamamlanamadı", http.StatusInternalServerError)
        return
    }

    // 5. Başarılı Yanıt
    w.Header().Set("Content-Type", "application/json")
    response := map[string]interface{}{
        "success":   true,
        "message": "Kategori başarıyla eklendi.",
        "category": categoryName, // Eklenen kategoriyi geri gönder
    }
    json.NewEncoder(w).Encode(response)
}
// Kategori silme işlemi
func DeleteCategoryHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    if !isAdmin(r) { // Yönetici kontrolü eklendi
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    categoryName := r.FormValue("categoryName")
    if categoryName == "" {
        http.Error(w, "Category name is required", http.StatusBadRequest)
        return
    }

    // Veritabanından silme işlemi (transaction kullanımı)
    tx, err := datahandlers.DB.Begin()
    if err != nil {
        utils.HandleErr(w, err, "Veritabanı işlemi başlatılamadı", http.StatusInternalServerError)
        return
    }
    defer tx.Rollback() // Hata durumunda işlemi geri al

    _, err = tx.Exec("DELETE FROM categories WHERE name = ?", categoryName)
    if err != nil {
        tx.Rollback() // Hata durumunda işlemi geri al
        utils.HandleErr(w, err, "Error deleting category", http.StatusInternalServerError)
        return
    }

    err = tx.Commit() // İşlemi onayla
    if err != nil {
        utils.HandleErr(w, err, "Veritabanı işlemi tamamlanamadı", http.StatusInternalServerError)
        return
    }

    // Başarılı yanıt
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// Kategorileri JSON formatında döndüren işleyici
func GetCategoriesHandler(w http.ResponseWriter, r *http.Request) {
    rows, err := datahandlers.DB.Query("SELECT name FROM categories")
    if err != nil {
        utils.HandleErr(w, err, "Kategoriler getirilirken hata oluştu.", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var categories []string
    for rows.Next() {
        var category string
        if err := rows.Scan(&category); err != nil {
            utils.HandleErr(w, err, "Kategori bilgileri okunurken hata oluştu.", http.StatusInternalServerError)
            return
        }
        categories = append(categories, category)
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string][]string{"categories": categories})
}