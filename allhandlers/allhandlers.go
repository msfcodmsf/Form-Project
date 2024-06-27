package allhandlers

import (
	"form-project/homehandlers"
	"form-project/morehandlers"
	"form-project/posthandlers"
	"net/http"
	"strings"
)

func Allhandlers() {
	//Bu örnek, sadece static/ dizinindeki dosyaların sunulmasını sağlar ve güvenlik risklerini azaltır.
	http.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[1:]
		if !strings.HasPrefix(path, "static/") {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, path)
	})

	http.HandleFunc("/google/login", homehandlers.HandleGoogleLogin)
	http.HandleFunc("/google/callback", homehandlers.HandleGoogleCallback)

	http.HandleFunc("/github/login", homehandlers.HandleGitHubLogin)
	http.HandleFunc("/github/callback", homehandlers.HandleGitHubCallback)

	http.HandleFunc("/", homehandlers.HomeHandler)
	http.HandleFunc("/register", homehandlers.RegisterHandler)
	http.HandleFunc("/login", homehandlers.LoginHandler)
	http.HandleFunc("/logout", homehandlers.LogoutHandler)
	http.HandleFunc("/sifreunut", homehandlers.SifreUnutHandler)
	http.HandleFunc("/createPost", posthandlers.CreatePostHandler)
	http.HandleFunc("/createComment", posthandlers.CreateCommentHandler)
	http.HandleFunc("/deletePost", posthandlers.DeletePostHandler)
	http.HandleFunc("/deleteComment", posthandlers.DeleteCommentHandler)
	http.HandleFunc("/vote", posthandlers.VoteHandler)
	http.HandleFunc("/viewPost", posthandlers.ViewPostHandler)
	http.HandleFunc("/myprofil", morehandlers.MyProfileHandler)
}
