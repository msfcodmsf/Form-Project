package main

import (
	"html/template"
	"log"
	"net/http"
	"sync"
)

var (
	tpl      = template.Must(template.ParseGlob("templates/*.html"))
	messages = []string{}
	msgMutex sync.Mutex
)

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/submit", submitHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("Server started on: http://localhost:8065")
	if err := http.ListenAndServe(":8065", nil); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	msgMutex.Lock()
	defer msgMutex.Unlock()
	tpl.ExecuteTemplate(w, "index.html", messages)
}

func submitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	msg := r.FormValue("message")
	if msg != "" {
		msgMutex.Lock()
		messages = append(messages, msg)
		msgMutex.Unlock()
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
