// posthandlers
package posthandlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"form-project/datahandlers"
	"form-project/homehandlers"
	"form-project/models"
	"form-project/morehandlers"
	"form-project/utils"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"
)

var currentUser *models.User

const maxUploadSize = 20 * 1024 * 1024 // 20 MB ile sınırlama
func CreatePostHandler(writer http.ResponseWriter, request *http.Request) {
    session, err := datahandlers.GetSession(request)
    if err != nil || session == nil {
        http.Redirect(writer, request, "/login", http.StatusSeeOther)
        return
    }

    // Fetch categories dynamically from the database (once, outside the if-else block)
	var categories []string
    rows, err := datahandlers.DB.Query("SELECT name FROM categories")
    if err != nil {
        utils.HandleErr(writer, err, "Kategoriler getirilirken hata oluştu", http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    for rows.Next() {
        var category string
        if err := rows.Scan(&category); err != nil {
            utils.HandleErr(writer, err, "Kategori taranırken hata oluştu", http.StatusInternalServerError)
            return
        }
        categories = append(categories, category)
    }

    if request.Method == http.MethodPost {
        // Form gönderme işlemi: Eğer istek bir POST isteği ise, form verileri işlenir.
        err := request.ParseMultipartForm(maxUploadSize)
        if err != nil {
            utils.HandleErr(writer, err, "Form verileri işlenirken hata oluştu", http.StatusBadRequest)
            return
        }

        title := request.FormValue("title")
        content := request.FormValue("content")
        categoriesJSON := request.FormValue("categories")

        // Unmarshal the categories, handling potential errors
		var selectedCategories []string
		if err := json.Unmarshal([]byte(categoriesJSON), &selectedCategories); err != nil {
			utils.HandleErr(writer, err, "Geçersiz kategori formatı.", http.StatusBadRequest)
			return
		}
		

        // Resim yükleme işlemi
        var imagePath string
        file, handler, err := request.FormFile("image")
        if err != nil && err != http.ErrMissingFile {
            utils.HandleErr(writer, err, "Resim yüklenirken hata oluştu", http.StatusBadRequest)
            return
        }
        if file != nil {
            defer file.Close()

            if handler.Size > maxUploadSize {
                utils.HandleErr(writer, fmt.Errorf("dosya boyutu limiti aşıyor"), "Dosya boyutu limiti aşıyor (20MB)", http.StatusBadRequest)
                return
            }

            ext := filepath.Ext(handler.Filename)
            allowedExtensions := map[string]bool{
                ".jpg":  true,
                ".jpeg": true,
                ".png":  true,
                ".gif":  true,
            }
            if !allowedExtensions[ext] {
                utils.HandleErr(writer, fmt.Errorf("desteklenmeyen resim formatı: %s", ext), "Desteklenmeyen resim formatı", http.StatusBadRequest)
                return
            }
            imageUUID := uuid.New().String()
            newFilename := imageUUID + ext
            uploadsDir := "./uploads"
            if _, err := os.Stat(uploadsDir); os.IsNotExist(err) {
                os.Mkdir(uploadsDir, 0755)
            }
            imagePath = filepath.Join(uploadsDir, newFilename)

            if err := saveImage(file, imagePath); err != nil {
                utils.HandleErr(writer, err, "Resim kaydedilirken hata oluştu", http.StatusInternalServerError)
                return
            }
        }

        categoriesData, err := json.Marshal(selectedCategories)
        if err != nil {
            utils.HandleErr(writer, err, "Internal server error", http.StatusInternalServerError)
            return
        }

        // Veritabanına kaydetme işlemi (moderated = 0 olarak)
        _, err = datahandlers.DB.Exec("INSERT INTO posts (user_id, title, content, categories, created_at, image_path, moderated) VALUES (?, ?, ?, ?, ?, ?, 0)",
            session.UserID, title, content, string(categoriesData), time.Now(), imagePath)
        if err != nil {
            utils.HandleErr(writer, err, "Internal server error", http.StatusInternalServerError)
            return
        }

        http.Redirect(writer, request, "/", http.StatusSeeOther)
        return
    }

    // Şablon verileri
    tmplData := struct {
        Categories []string
        LoggedIn   bool
        IsAdmin    bool
        IsModerator bool
    }{
        Categories: categories,
        LoggedIn:   session != nil,
        IsAdmin:    isAdmin(request), 
        IsModerator: homehandlers.IsModerator(request),
    }

    // Şablonu ayrıştır ve işle
    tmpl, err := template.ParseFiles("templates/createPost.html")
    if err != nil {
        utils.HandleErr(writer, err, "Internal server error", http.StatusInternalServerError)
        return
    }

    err = tmpl.Execute(writer, tmplData)
    if err != nil {
        utils.HandleErr(writer, err, "Internal server error", http.StatusInternalServerError)
    }
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


// Fotoğrafı kaydet
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

// Bir gönderiye yeni bir yorum eklemek için kullanılan HTTP işleyicisidir.
func CreateCommentHandler(w http.ResponseWriter, r *http.Request) {
	session, err := datahandlers.GetSession(r)
	if err != nil || session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		err := r.ParseMultipartForm(32 << 20) // 32 MB maksimum upload boyutu
		if err != nil {
			utils.HandleErr(w, err, "Error parsing multipart form", http.StatusBadRequest)
			return
		}

		postIDStr := r.FormValue("post_id")
		content := r.FormValue("content")

		if content == "" {
			utils.HandleErr(w, nil, "Content is required", http.StatusBadRequest)
			return
		}

		postID, err := strconv.Atoi(postIDStr)
		if err != nil {
			utils.HandleErr(w, err, "Invalid post ID", http.StatusBadRequest)
			return
		}

		// Yorum fotoğrafını işle
		var commentImagePath string
		newFilename := ""

		file, handler, err := r.FormFile("commentImage")
		if err == nil { // Dosya varsa işle
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

			// Benzersiz dosya adı oluştur ve newFilename'e ata
			imageUUID := uuid.New().String()
			newFilename = imageUUID + ext

			// uploads dizininin var olup olmadığını kontrol et, yoksa oluştur
			uploadsDir := "./uploads"
			if _, err := os.Stat(uploadsDir); os.IsNotExist(err) {
				os.Mkdir(uploadsDir, 0755) // Klasörü oluştur
			}

			// Kaydedilecek dosyanın tam yolunu oluştur
			commentImagePath = filepath.Join(uploadsDir, newFilename)

			// Fotoğrafı kaydet
			if err := saveImage(file, commentImagePath); err != nil {
				utils.HandleErr(w, err, "Error saving image", http.StatusInternalServerError)
				return
			}
		} else if err != http.ErrMissingFile { // Dosya yoksa hata ver
			utils.HandleErr(w, err, "Error getting image", http.StatusBadRequest)
			return
		}

		// Veritabanına kaydet (commentImagePath ile birlikte)
		_, err = datahandlers.DB.Exec("INSERT INTO comments (post_id, user_id, content, created_at, image_path) VALUES (?, ?, ?, ?, ?)",
			postID, session.UserID, content, time.Now(), newFilename)
		if err != nil {
			utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/viewPost?id=%d", postID), http.StatusSeeOther)
		return
	}
}

// Belirli bir yorumu silmek için kullanılan HTTP işleyicisidir.
func DeletePostHandler(w http.ResponseWriter, r *http.Request) {
	session, err := datahandlers.GetSession(r)
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
	err = datahandlers.DB.QueryRow("SELECT user_id FROM posts WHERE id = ?", postID).Scan(&userID)
	if err != nil {
		utils.HandleErr(w, err, "Post not found", http.StatusNotFound)
		return
	}

	user, err := morehandlers.GetUserByID(session.UserID)
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	if userID != session.UserID && user.Role != "moderator" && user.Role != "admin" {
		// Set a cookie with the error message for the alert
		http.SetCookie(w, &http.Cookie{
			Name:  "delete_error",
			Value: "You can only delete your own posts",
			Path:  "/", // Make sure the cookie is accessible on all pages
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	_, err = datahandlers.DB.Exec("UPDATE posts SET deleted = 1 WHERE id = ?", postID)
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Belirli bir yorumu silmek için kullanılan HTTP işleyicisidir.
func DeleteCommentHandler(w http.ResponseWriter, r *http.Request) {
	session, err := datahandlers.GetSession(r)
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
	err = datahandlers.DB.QueryRow("SELECT user_id, post_id FROM comments WHERE id = ?", commentID).Scan(&userID, &postID)
	if err != nil {
		utils.HandleErr(w, err, "Comment not found", http.StatusNotFound)
		return
	}

	var postOwnerID int
	err = datahandlers.DB.QueryRow("SELECT user_id FROM posts WHERE id = ?", postID).Scan(&postOwnerID)
	if err != nil {
		utils.HandleErr(w, err, "Post not found", http.StatusNotFound)
		return
	}

	if userID != session.UserID && postOwnerID != session.UserID {
		http.Error(w, "You can only delete your own comments or comments on your posts", http.StatusForbidden)
		return
	}

	_, err = datahandlers.DB.Exec("UPDATE comments SET deleted = 1 WHERE id = ?", commentID)
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/viewPost?id=%d", postID), http.StatusSeeOther)
}

// Gönderilere veya yorumlara oy vermek (beğenmek/beğenmemek) için kullanılır.
func VoteHandler(w http.ResponseWriter, r *http.Request) {
	session, err := datahandlers.GetSession(r)
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
		utils.HandleErr(w, err, "Invalid vote type", http.StatusBadRequest)
		return
	}

	var existingVoteType sql.NullInt64
	var query string

	if postID != "" {
		query = "SELECT vote_type FROM votes WHERE user_id = ? AND post_id = ?"
		err = datahandlers.DB.QueryRow(query, session.UserID, postID).Scan(&existingVoteType)
	} else if commentID != "" {
		query = "SELECT vote_type FROM votes WHERE user_id = ? AND comment_id = ?"
		err = datahandlers.DB.QueryRow(query, session.UserID, commentID).Scan(&existingVoteType)
	}

	if err != nil && err != sql.ErrNoRows {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	if existingVoteType.Valid {
		if existingVoteType.Int64 == int64(voteType) {
			if postID != "" {
				query = "DELETE FROM votes WHERE user_id = ? AND post_id = ?"
				_, err = datahandlers.DB.Exec(query, session.UserID, postID)
			} else if commentID != "" {
				query = "DELETE FROM votes WHERE user_id = ? AND comment_id = ?"
				_, err = datahandlers.DB.Exec(query, session.UserID, commentID)
			}
		} else {
			if postID != "" {
				query = "UPDATE votes SET vote_type = ? WHERE user_id = ? AND post_id = ?"
				_, err = datahandlers.DB.Exec(query, voteType, session.UserID, postID)
			} else if commentID != "" {
				query = "UPDATE votes SET vote_type = ? WHERE user_id = ? AND comment_id = ?"
				_, err = datahandlers.DB.Exec(query, voteType, session.UserID, commentID)
			}
		}
	} else {
		if postID != "" {
			query = "INSERT INTO votes (user_id, post_id, vote_type) VALUES (?, ?, ?)"
			_, err = datahandlers.DB.Exec(query, session.UserID, postID, voteType)
		} else if commentID != "" {
			query = "INSERT INTO votes (user_id, comment_id, vote_type) VALUES (?, ?, ?)"
			_, err = datahandlers.DB.Exec(query, session.UserID, commentID, voteType)
		}
	}

	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Oy sayısını yeniden hesapla ve JSON olarak dön
	var likeCount, dislikeCount int
	if postID != "" {
		err = datahandlers.DB.QueryRow(`SELECT 
			COALESCE(SUM(CASE WHEN vote_type = 1 THEN 1 ELSE 0 END), 0) AS like_count,
			COALESCE(SUM(CASE WHEN vote_type = -1 THEN 1 ELSE 0 END), 0) AS dislike_count
			FROM votes WHERE post_id = ?`, postID).Scan(&likeCount, &dislikeCount)
	} else if commentID != "" {
		err = datahandlers.DB.QueryRow(`SELECT 
			COALESCE(SUM(CASE WHEN vote_type = 1 THEN 1 ELSE 0 END), 0) AS like_count,
			COALESCE(SUM(CASE WHEN vote_type = -1 THEN 1 ELSE 0 END), 0) AS dislike_count
			FROM votes WHERE comment_id = ?`, commentID).Scan(&likeCount, &dislikeCount)
	}

	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := map[string]int{"like_count": likeCount, "dislike_count": dislikeCount}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Belirli bir gönderiyi ve altındaki yorumları görüntülemek için kullanılan HTTP işleyicisidir.
func ViewPostHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := datahandlers.GetSession(r)

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	postIDStr := r.URL.Query().Get("id")
	if postIDStr == "" {
		http.Error(w, "Post ID required", http.StatusBadRequest)
		return
	}

	postID, err := strconv.Atoi(postIDStr)
	if err != nil {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	var post models.Post
	var categoriesJSON string
	err = datahandlers.DB.QueryRow(`SELECT posts.id, posts.user_id, posts.title, posts.content, posts.categories, posts.created_at, users.username, posts.image_path, 
    COALESCE(SUM(CASE WHEN votes.vote_type = 1 THEN 1 ELSE 0 END), 0) AS like_count,
    COALESCE(SUM(CASE WHEN votes.vote_type = -1 THEN 1 ELSE 0 END), 0) AS dislike_count
    FROM posts
    JOIN users ON posts.user_id = users.id
    LEFT JOIN votes ON votes.post_id = posts.id
    WHERE posts.id = ? AND posts.deleted = 0
    GROUP BY posts.id`, postID).Scan(&post.ID, &post.UserID, &post.Title, &post.Content, &categoriesJSON, &post.CreatedAt, &post.Username, &post.ImagePath, &post.LikeCount, &post.DislikeCount)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Post not found", http.StatusNotFound)
		} else {
			log.Println("Error querying post:", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	var categories []string
	err = json.Unmarshal([]byte(categoriesJSON), &categories)
	if err != nil {
		utils.HandleErr(w, err, "Error parsing categories", http.StatusInternalServerError)
		return
	}

	post.CreatedAtFormatted = post.CreatedAt.Format("2006-01-02 15:04")
	post.Categories = categories

	rows, err := datahandlers.DB.Query(`
        SELECT c.id, c.post_id, c.user_id, c.content, c.created_at, u.username, c.image_path, 
               COALESCE(SUM(CASE WHEN v.vote_type = 1 THEN 1 ELSE 0 END), 0) AS like_count,
               COALESCE(SUM(CASE WHEN v.vote_type = -1 THEN 1 ELSE 0 END), 0) AS dislike_count
        FROM comments c
        JOIN users u ON c.user_id = u.id
        LEFT JOIN votes v ON v.comment_id = c.id
        WHERE c.post_id = ? AND c.deleted = 0
        GROUP BY c.id, c.post_id, c.user_id, c.content, c.created_at, u.username, c.image_path 
        ORDER BY c.created_at DESC`, postID)
	if err != nil {
		log.Println("Error querying comments:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var comments []models.Comment // Comment struct'ını kullanın, posthandlers.Comment değil
	for rows.Next() {
		var comment models.Comment
		err := rows.Scan(&comment.ID, &comment.PostID, &comment.UserID, &comment.Content, &comment.CreatedAt, &comment.Username, &comment.ImagePath, &comment.LikeCount, &comment.DislikeCount)
		// image_path sütunu created_at'den sonra geldiği için sıralaması değiştirildi.
		if err != nil {
			log.Println("Error scanning comment:", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		comment.CreatedAtFormatted = comment.CreatedAt.Format("2006-01-02 15:04")
		comments = append(comments, comment)
	}
	if err := rows.Err(); err != nil {
		log.Println("Rows error:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	data := struct {
        Post        models.Post
        Comments    []models.Comment
        LoggedIn    bool
        IsModerator bool
        CurrentUser *models.User
    }{
        Post:        post,
        Comments:    comments,
        LoggedIn:    session != nil,
        IsModerator: homehandlers.IsModerator(r),
        CurrentUser: currentUser, // CurrentUser'ı ata
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
