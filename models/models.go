package models

import (
	"database/sql"
	"time"
)

type User struct {
	ID                 int            `validate:"-"`
	Email              string         `validate:"required,email"`
	Username           sql.NullString // Google kayıtta bazen boş olabilir
	Password           sql.NullString // Google kayıtta şifre alanı gereksiz olabilir
	ProfilePicturePath sql.NullString // Profil fotoğrafının yolu
	Role               string         // Kullanıcının rolü (admin, moderator, member)
}

type RegisterTemplateData struct {
	ErrorMessages map[string]string
	Email         string
	Username      string
}

type ModeratorRequest struct {
	ID       int
	UserID   int
	Reason   string
	Username string
}

type Report struct {
	ID            int
	PostID        int
	PostTitle     string // Rapor edilen gönderinin başlığı
	ModeratorID   int
	ModeratorName string // Raporu yapan moderatörün adı
	Reason        string
	Status        string // pending, approved, rejected
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
	ImagePath           string
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
	ImagePath          string
}
