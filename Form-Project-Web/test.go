package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestVoteHandler(t *testing.T) {
	// Initialize a post for testing
	_, err := db.Exec("INSERT INTO posts (user_id, title, content, created_at) VALUES (?, ?, ?, ?)", 1, "Test Post", "Test Content", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var postID int
	err = db.QueryRow("SELECT id FROM posts WHERE title = ?", "Test Post").Scan(&postID)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		voteType         string
		expectedCode     int
		expectedLikes    int
		expectedDislikes int
	}{
		{"like", http.StatusOK, 1, 0},
		{"dislike", http.StatusOK, 0, 1},
		{"invalid", http.StatusBadRequest, 0, 1},
	}

	for _, test := range tests {
		req, err := http.NewRequest("POST", "/posts/"+strconv.Itoa(postID)+"/vote?type="+test.voteType, nil)
		if err != nil {
			t.Fatal(err)
		}
		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(voteHandler)
		handler.ServeHTTP(rr, req)

		if status := rr.Code; status != test.expectedCode {
			t.Errorf("handler returned wrong status code: got %v want %v", status, test.expectedCode)
		}

		var post Post
		err = db.QueryRow(`SELECT id, user_id, title, content, created_at,
                            (SELECT COUNT(*) FROM votes WHERE post_id = posts.id AND vote_type = 1) AS like_count,
                            (SELECT COUNT(*) FROM votes WHERE post_id = posts.id AND vote_type = -1) AS dislike_count
                            FROM posts WHERE id = ?`, postID).Scan(&post.ID, &post.UserID, &post.Title, &post.Content, &post.CreatedAt, &post.LikeCount, &post.DislikeCount)
		if err != nil {
			t.Fatal(err)
		}

		if post.LikeCount != test.expectedLikes {
			t.Errorf("handler returned wrong like count: got %v want %v", post.LikeCount, test.expectedLikes)
		}
		if post.DislikeCount != test.expectedDislikes {
			t.Errorf("handler returned wrong dislike count: got %v want %v", post.DislikeCount, test.expectedDislikes)
		}
	}
}
