package main

import (
	"form-project/allhandlers"
	"form-project/datahandlers" // Veritabanı bağlantı bilgileri
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	datahandlers.SetDB()
	defer datahandlers.DB.Close()

	datahandlers.CreateTables()

	allhandlers.Allhandlers()

	log.Println("Server started at :8065")
	http.ListenAndServe(":8065", nil)
}
