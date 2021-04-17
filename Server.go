package main

import (
	"net/http"
	"io"
	"fmt"
	"encoding/json"
	"crypto/sha256"
	"time"
	"strconv"
)

var Mutex chan int = make(chan int, 1)

type UserData struct {
	Login string    `json:"login"`
	Password string `json:"password"`
}

type User struct {
	ID int
	login string
	passwordHash [sha256.Size]byte
}

var userDB []User

type Session struct {
	ID int
	userID int
	openedDate time.Time
	expirationDate time.Time
}

var SessID = 1

var SessionDB []Session

func loginHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Access-Control-Allow-Methods", "OPTIONS, POST")
	w.Header().Add("Access-Control-Allow-Headers", "content-type")
	w.Header().Add("Access-Control-Allow-Origin","*")
	if req.Method == "OPTIONS" {
		w.WriteHeader(204)
	} else if req.Method == "POST" {
		data, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {return }
		var v UserData
		err = json.Unmarshal(data, &v)
		if err != nil {fmt.Println(err); return}
		
		for _, u := range userDB {
			if u.passwordHash == sha256.Sum256([]byte(v.Password)) {
				io.WriteString(w, fmt.Sprint(createSession(u.ID)))
				return
			}
		}
		
		io.WriteString(w, "unknown")
	} else {
		w.WriteHeader(405)
	}
}

func createSession(userID int) int {
	now := time.Now()
	sess := Session{SessID, userID, now, now.Add(time.Hour)}
	SessID++
	SessionDB = append(SessionDB,sess)
	return sess.ID
}

func getHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Access-Control-Allow-Methods", "OPTIONS, GET")
	w.Header().Add("Access-Control-Allow-Headers", "content-type, session-id")
	w.Header().Add("Access-Control-Allow-Origin","*")
	if req.Method == "OPTIONS" {
		w.WriteHeader(204)
	} else if req.Method == "GET" {
		SID, err := strconv.Atoi(req.Header.Get("Session-ID"))
		if err != nil {
			return
		}
		
		for _, s := range SessionDB {
			if s.ID == SID {
				if time.Now().After(s.expirationDate) {
					DeleteSession(s.ID)
					w.WriteHeader(401)
					return
				}
				io.WriteString(w, "success")
				return
			}
		}
		w.WriteHeader(401)
	} else {
		w.WriteHeader(405)
	}
}

func DeleteSession(sessID int) {
	<-Mutex
	i := 0
	var s Session
	for i, s = range SessionDB {
		if s.ID == sessID {
			break
		}
	}
	
	SessionDB = append(SessionDB[:i], SessionDB[i+1:]...)
	Mutex <- 1
}

func main() {
	Mutex <- 1
	userDB = append(userDB, User{1, "admin", sha256.Sum256([]byte("Test"))})
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/data", getHandler)
	
	err := http.ListenAndServe(":8080", nil)
	panic(err)
}
