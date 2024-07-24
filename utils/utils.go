// utils
package utils

import (
	"encoding/json"
	"log"
	"net/http"
)

// utils.go içindeki HandleErr fonksiyonu

func HandleErr(w http.ResponseWriter, err error, message string, statusCode int) {
    log.Println(err)
    w.WriteHeader(statusCode)
    w.Header().Set("Content-Type", "application/json")

    // Flusher'a dönüştür
    flusher, ok := w.(http.Flusher)
    if ok {
        flusher.Flush() // Yanıtı gönder
    }

    // Hata mesajını JSON olarak gönder
    response := map[string]string{"error": message}
    json.NewEncoder(w).Encode(response)
}

