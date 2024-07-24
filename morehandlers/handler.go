// morehandlers
package morehandlers // Kullanıcı profili ve ilgili işlemleri yöneten paket

import (
	"database/sql"              // Veritabanı işlemleri için
	"encoding/json"             // JSON verilerini işlemek için
	"fmt"                       // Formatlama ve çıktı işlemleri için
	"form-project/datahandlers" // Veritabanı bağlantısı ve oturum yönetimi için
	"form-project/models"
	"form-project/utils" // Hata yönetimi gibi yardımcı fonksiyonlar için
	"html/template"      // HTML şablonlarını işlemek için
	"io"
	"mime/multipart"
	"net/http" // HTTP isteklerini ve yanıtlarını yönetmek için
	"os"
	"path/filepath"
	"strings" // String (metin) işlemleri için

	// Zaman ve tarih işlemleri için
	"github.com/google/uuid"
)

// Post yapısı, bir gönderinin verilerini temsil eder.

// User yapısı, bir kullanıcıyı temsil eder.

// kullanıcının profil sayfasını oluşturur ve görüntüler.
func MyProfileHandler(w http.ResponseWriter, r *http.Request) {
	session, err := datahandlers.GetSession(r)
	if err != nil || session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user, err := GetUserByID(session.UserID)
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	ownPosts, err := getOwnPosts(session.UserID)
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	likedPosts, err := getLikedPosts(session.UserID)
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("templates/myprofil.html")
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	data := struct {
		User       *models.User
		OwnPosts   []models.Post
		LikedPosts []models.Post
	}{
		User:       user,
		OwnPosts:   ownPosts,
		LikedPosts: likedPosts,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// Belirtilen kullanıcı ID'sine ait gönderileri veritabanından çeker.
func getOwnPosts(userID int) ([]models.Post, error) {
	query := `SELECT posts.id, posts.user_id, posts.title, posts.content, posts.categories, posts.created_at, users.username,
                     COALESCE(SUM(CASE WHEN votes.vote_type = 1 THEN 1 ELSE 0 END), 0) AS like_count,
                     COALESCE(SUM(CASE WHEN votes.vote_type = -1 THEN 1 ELSE 0 END), 0) AS dislike_count,
                     (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id AND comments.deleted = 0) AS comment_count
              FROM posts
              JOIN users ON posts.user_id = users.id
              LEFT JOIN votes ON votes.post_id = posts.id
              WHERE posts.user_id = ? AND posts.deleted = 0
              GROUP BY posts.id
              ORDER BY posts.created_at DESC`

	rows, err := datahandlers.DB.Query(query, userID)
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

// Belirtilen kullanıcı ID'sinin beğendiği gönderileri veritabanından çeker.
func getLikedPosts(userID int) ([]models.Post, error) {
	query := `
		SELECT posts.id, posts.user_id, posts.title, posts.content, posts.categories, posts.created_at, users.username,
		       COALESCE(SUM(CASE WHEN votes.vote_type = 1 THEN 1 ELSE 0 END), 0) AS like_count,
		       COALESCE(SUM(CASE WHEN votes.vote_type = -1 THEN 1 ELSE 0 END), 0) AS dislike_count,
		       (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id AND comments.deleted = 0) AS comment_count
		FROM posts
		JOIN users ON posts.user_id = users.id
		LEFT JOIN votes ON votes.post_id = posts.id
		WHERE posts.id IN (SELECT post_id FROM votes WHERE user_id = ? AND vote_type = 1)
		AND posts.deleted = 0
		GROUP BY posts.id, posts.user_id, posts.title, posts.content, posts.categories, posts.created_at, users.username
		ORDER BY posts.created_at DESC`

	rows, err := datahandlers.DB.Query(query, userID)
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

// Belirtilen kullanıcı ID'sine sahip kullanıcıyı veritabanından çeker.
func GetUserByID(userID int) (*models.User, error) {
	var user models.User
	query := "SELECT id, email, username, password, profile_picture_path, role FROM users WHERE id = ?"
	err := datahandlers.DB.QueryRow(query, userID).Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.ProfilePicturePath, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user with ID %d not found", userID)
		}
		return nil, err
	}
	return &user, nil
}

const maxUploadSize = 20 * 1024 * 1024 // 20 MB
func UploadProfilePictureHandler(w http.ResponseWriter, r *http.Request) {
	session, err := datahandlers.GetSession(r)
	if err != nil || session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	file, handler, err := r.FormFile("profilePicture")
	if err != nil {
		utils.HandleErr(w, err, "Error getting image", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Dosya boyutunu kontrol et
	if handler.Size > maxUploadSize {
		utils.HandleErr(w, fmt.Errorf("file size exceeds limit"), "File size exceeds limit (20MB)", http.StatusBadRequest)
		return
	}

	// Dosya uzantısını kontrol et
	ext := filepath.Ext(handler.Filename)
	allowedExtensions := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
	}
	if !allowedExtensions[ext] {
		utils.HandleErr(w, fmt.Errorf("unsupported image format: %s", ext), "Unsupported image format", http.StatusBadRequest)
		return
	}

	// Benzersiz dosya adı oluştur
	imageUUID := uuid.New().String()
	newFilename := imageUUID + ext

	// uploads dizininin var olup olmadığını kontrol et, yoksa oluştur
	uploadsDir := "./uploads"
	if _, err := os.Stat(uploadsDir); os.IsNotExist(err) {
		os.Mkdir(uploadsDir, 0755)
	}

	// Kaydedilecek dosyanın tam yolunu oluştur
	imagePath := filepath.Join(uploadsDir, newFilename)

	// Fotoğrafı kaydet
	if err := saveImage(file, imagePath); err != nil {
		utils.HandleErr(w, err, "Error saving image", http.StatusInternalServerError)
		return
	}

	// Veritabanındaki profile_picture_path alanını güncelle
	_, err = datahandlers.DB.Exec("UPDATE users SET profile_picture_path = ? WHERE id = ?", newFilename, session.UserID)
	if err != nil {
		utils.HandleErr(w, err, "Error updating profile picture path", http.StatusInternalServerError)
		return
	}

	// Yüklenen dosyanın adını geri döndür
	fmt.Fprint(w, newFilename)
}

func saveImage(file multipart.File, imagePath string) error {
	// Dosyayı aç
	dst, err := os.Create(imagePath)
	if err != nil {
		return fmt.Errorf("dosya oluşturulamadı: %w", err)
	}
	defer dst.Close()

	// Gelen veriyi dosyaya kopyala
	_, err = io.Copy(dst, file)
	if err != nil {
		return fmt.Errorf("dosya kopyalanamadı: %w", err)
	}

	return nil
}
