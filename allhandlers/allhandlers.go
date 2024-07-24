// allhandlers
package allhandlers // Bu paket, tüm HTTP istek işleyicilerini (handler) merkezi bir yerde toplar.

import (  // Gerekli paketler import edilir.
    "form-project/homehandlers"     // Ana sayfa ve oturum işlemleriyle ilgili işleyiciler.
    "form-project/morehandlers"     // Diğer özel işlevler için işleyiciler.
    "form-project/posthandlers"     // Gönderi (post) işlemleri için işleyiciler.
    "net/http"                    // HTTP sunucu ve istek/cevap yönetimi için standart Go paketi.
    "strings"                      // String (karakter dizisi) işleme fonksiyonları.
)

func Allhandlers() { // Bu fonksiyon, tüm istek işleyicilerini kaydeder.
    // Statik Dosya Sunumu:
    http.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) { // "/static/" ile başlayan istekler için statik dosya sunar.
        path := r.URL.Path[1:]                                                 // İstek yolundan ilk "/" karakterini kaldırır.
        if !strings.HasPrefix(path, "static/") {                                  // Yol "static/" ile başlamazsa...
            http.NotFound(w, r)                                                   // 404 Not Found yanıtı gönderir.
            return                                                               // Fonksiyondan çıkar.
        }
        http.ServeFile(w, r, path)                                                // Statik dosyayı sunar.
    })
    http.HandleFunc("/uploadProfilePicture", morehandlers.UploadProfilePictureHandler)
    http.HandleFunc("/google/register", homehandlers.HandleGoogleRegister)
    http.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("./uploads"))))
    http.HandleFunc("/upload", homehandlers.UploadHandler)

    // Google Oturum İşlemleri:
    http.HandleFunc("/google/login", homehandlers.HandleGoogleLogin)        // Google ile oturum açma işlemi için işleyici.
    http.HandleFunc("/google/callback", homehandlers.HandleGoogleCallback)  // Google'dan dönen callback isteği için işleyici.

    // GitHub Oturum İşlemleri:
    http.HandleFunc("/github/login", homehandlers.HandleGitHubLogin)         // GitHub ile oturum açma işlemi için işleyici.
    http.HandleFunc("/github/callback", homehandlers.HandleGitHubCallback)   // GitHub'dan dönen callback isteği için işleyici.
    // Facebook Oturum İşlemleri:
    http.HandleFunc("/facebook/login", homehandlers.HandleFacebookLogin)         
    http.HandleFunc("/facebook/callback", homehandlers.HandleFacebookCallback)

    // Diğer İşleyiciler:
    http.HandleFunc("/", homehandlers.HomeHandler)             // Ana sayfa için işleyici.
    http.HandleFunc("/register", homehandlers.RegisterHandler)   // Kayıt olma sayfası için işleyici.
    http.HandleFunc("/login", homehandlers.LoginHandler)       // Oturum açma sayfası için işleyici.
    http.HandleFunc("/logout", homehandlers.LogoutHandler)     // Oturum kapatma işlemi için işleyici.
    http.HandleFunc("/sifreunut", homehandlers.SifreUnutHandler) // Şifre sıfırlama işlemi için işleyici.

    // Gönderi İşlemleri:
    http.HandleFunc("/createPost", posthandlers.CreatePostHandler)        // Gönderi oluşturma işlemi için işleyici.
    http.HandleFunc("/createComment", posthandlers.CreateCommentHandler)  // Yorum oluşturma işlemi için işleyici.
    http.HandleFunc("/deletePost", posthandlers.DeletePostHandler)        // Gönderi silme işlemi için işleyici.
    http.HandleFunc("/deleteComment", posthandlers.DeleteCommentHandler)  // Yorum silme işlemi için işleyici.
    http.HandleFunc("/vote", posthandlers.VoteHandler)                    // Oy verme işlemi için işleyici.
    http.HandleFunc("/viewPost", posthandlers.ViewPostHandler)            // Gönderiyi görüntüleme işlemi için işleyici.

    // Profil İşlemleri:
    http.HandleFunc("/myprofil", morehandlers.MyProfileHandler)           // Kullanıcının profilini görüntüleme işlemi için işleyici.

    http.HandleFunc("/admin", homehandlers.AdminPanelHandler) // morehandlers.MyProfileHandler yerine
    http.HandleFunc("/admin/delete-user", homehandlers.DeleteUserHandler) // Örnek URL
    http.HandleFunc("/checkAdminStatus", homehandlers.CheckAdminStatusHandler)
    http.HandleFunc("/updateUserRole", homehandlers.UpdateUserRoleHandler)
    http.HandleFunc("/moderatör", homehandlers.ModeratorPanelHandler)
    http.HandleFunc("/onayla", homehandlers.OnaylaHandler)
    http.HandleFunc("/reddet", homehandlers.ReddetHandler)
    http.HandleFunc("/moderator-request", homehandlers.HandleModeratorRequest)
    http.HandleFunc("/approve-moderator-request", homehandlers.ApproveModeratorRequestHandler)
    http.HandleFunc("/reject-moderator-request", homehandlers.RejectModeratorRequestHandler)
    http.HandleFunc("/report-post", homehandlers.ReportPostHandler) // posthandlers yerine homehandlers
    http.HandleFunc("/approve-report", homehandlers.ApproveReportHandler)
    http.HandleFunc("/reject-report", homehandlers.RejectReportHandler)
    http.HandleFunc("/addCategory", homehandlers.AddCategoryHandler)
    http.HandleFunc("/deleteCategory", homehandlers.DeleteCategoryHandler)
    http.HandleFunc("/getCategories", homehandlers.GetCategoriesHandler)
}
