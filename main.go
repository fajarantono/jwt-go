package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "@uburubur256"
	dbname   = "db_learn-jwt"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"message"`
}

func main() {

	router := mux.NewRouter()

	router.HandleFunc("/", home).Methods("GET")
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenverifyMiddleWare(ProtectedEndpoint)).Methods("GET")

	log.Println("listen on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", router))
}

func respondWithError(w http.ResponseWriter, status int, error Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
}

func responseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

func home(res http.ResponseWriter, req *http.Request) {
	fmt.Fprint(res, "<b>WELCOME TO REST API</b>")
}

func signup(w http.ResponseWriter, r *http.Request) {
	var user User
	var error Error

	db := setupDB()

	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Email is required."
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "Password is required."
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	user.Password = getHash([]byte(user.Password))

	stmt := "INSERT INTO users (email, password) values($1, $2) RETURNING id"
	err := db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)

	//checkErr(err)

	if err != nil {
		error.Message = "Server error"
		respondWithError(w, http.StatusInternalServerError, error)
		return
	}

	user.Password = ""
	// w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	// w.Header().Set("Access-Control-Allow-Origin", "*")

	w.Header().Set("Content_Type", "application/json")
	responseJSON(w, user)
}

func login(w http.ResponseWriter, r *http.Request) {
	var user User
	var jwt JWT
	var error Error
	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Email is required."
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "Password is required."
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	password := user.Password

	db := setupDB()
	row := db.QueryRow("SELECT * FROM users WHERE email=$1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)

	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "The user does not exist"
			respondWithError(w, http.StatusBadRequest, error)
			return
		} else {
			log.Fatal(err)
		}
	}

	hashedPassword := user.Password

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))

	if err != nil {
		error.Message = "Invalid Password"
		respondWithError(w, http.StatusUnauthorized, error)
		return
	}
	//spew.Dump(user)

	token, err := GenerateToken(user)
	if err != nil {
		log.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	responseJSON(w, jwt)

	// fmt.Println(token)
}

func ProtectedEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("ProtectedEndpoint invoked.")
}

func TokenverifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}

				return []byte("secret"), nil
			})

			if error != nil {
				//fmt.Println("cok")
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}

			//spew.Dump(token)
			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}

		} else {
			errorObject.Message = "Invalid token."
			respondWithError(w, http.StatusUnauthorized, errorObject)
			return
		}

		//fmt.Println(bearerToken)
	})
}

// DB set up
func setupDB() *sql.DB {
	dbinfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	db, err := sql.Open("postgres", dbinfo)

	checkErr(err)

	return db
}

// Function for handling errors
func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func getHash(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, 10)
	if err != nil {
		log.Fatal(err)
	}
	return string(hash)
}

func GenerateToken(user User) (string, error) {
	var err error
	secret := "secret"

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "course",
	})

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		log.Fatal(err)
	}

	//spew.Dump(token)

	return tokenString, nil
}
