package main

import (
	"crypto/sha1"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	_ "github.com/lib/pq"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

// Template is the representation of a parsed template. The *parse.Tree field is exported only for use by html/template and should be treated as unexported by all other clients.
var tpl *template.Template

// DB is a database handle representing a pool of zero or more underlying connections. It's safe for concurrent use by multiple goroutines.
var db *sql.DB
var dbSessions = map[string]string{}

type user struct {
	ID         int
	Firstname  string
	Lastname   string
	Email      string
	Password   string
	ProfilePic string
	Active     bool
	JoinedDate time.Time
	LastActive time.Time
}

func allUser() ([]user, error) {
	// The make built-in function allocates and initializes an object of type slice, map, or chan (only).
	// func(t Type, size ...IntegerType) Type
	users := make([]user, 0)
	rows, err := db.Query("SELECT * FROM cms_user;")
	if err != nil {
		return users, err
	}

	// Next prepares the next result row for reading with the Scan method. It returns true on success, or false if there is no next result row or an error happened while preparing it.
	// func (*sql.Rows).Next() bool
	for rows.Next() {
		var user user

		// Scan copies the columns in the current row into the values pointed at by dest. The number of values in dest must be the same as the number of columns in Rows.
		// func (*sql.Rows).Scan(dest ...interface{}) error
		err := rows.Scan(&user.ID, &user.Firstname, &user.Lastname, &user.Email, &user.Password, &user.ProfilePic, &user.Active, &user.JoinedDate, &user.LastActive)
		if err != nil {
			return users, err
		}
		users = append(users, user)
	}
	return users, err
}

func init() {
	// Must is a helper that wraps a call to a function returning (*Template, error) and panics if the error is non-nil.
	// emplate.Must(t *template.Template, err error) *template.Template

	// ParseGlob creates a new Template and parses the template definitions from the files identified by the pattern.
	// func template.ParseGlob(pattern string) (*template.Template, error)
	tpl = template.Must(template.ParseGlob("templates/*.html"))

	var err error
	connStr := "postgres://postgres:password@localhost/postgres?sslmode=disable"

	// Open opens a database specified by its database driver name and a driver-specific data source name, usually consisting of at least a database name and connection information.
	// func sql.Open(driverName string, dataSourceName string) (*sql.DB, error)
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	// Ping verifies a connection to the database is still alive, establishing a connection if necessary.
	// func (*sql.DB).Ping() error
	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Successfully connected to database")
}

func main() {
	// Close closes the database and prevents new queries from starting. Close then waits for all queries that have started processing on the server to finish.
	// It is rare to Close a DB, as the DB handle is meant to be long-lived and shared between many goroutines.
	// func (*sql.DB).Close() error
	defer db.Close()

	// HandleFunc registers the handler function for the given pattern in the DefaultServeMux. The documentation for ServeMux explains how patterns are matched.
	// func http.HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
	http.HandleFunc("/", index)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/welcome", welcome)
	http.HandleFunc("/upload", upload)

	// Handle registers the handler for the given pattern in the DefaultServeMux. The documentation for ServeMux explains how patterns are matched.
	// func http.Handle(pattern string, handler http.Handler)

	// stripPrefix returns a handler that serves HTTP requests by removing the given prefix from the request URL's Path (and RawPath if set) and invoking the handler h.
	// func http.StripPrefix(prefix string, h http.Handler) http.Handler
	http.Handle("/public/", http.StripPrefix("/public", http.FileServer(http.Dir("./public"))))
	http.Handle("favicon.ico", http.NotFoundHandler())
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// A ResponseWriter interface is used by an HTTP handler to construct an HTTP response.
// A Request represents an HTTP request received by a server or to be sent by a client.
func index(w http.ResponseWriter, r *http.Request) {
	if isLoggedIn(r) {
		// Redirect replies to the request with a redirect to url, which may be a path relative to the request path.
		// func http.Redirect(w http.ResponseWriter, r *http.Request, url string, code int)
		http.Redirect(w, r, "/welcome", http.StatusSeeOther)
		return
	}

	// ExecuteTemplate applies the template associated with t that has the given name to the specified data object and writes the output to wr.
	// func (*template.Template).ExecuteTemplate(wr io.Writer, name string, data interface{}) error
	err := tpl.ExecuteTemplate(w, "index.html", dbSessions)
	if err != nil {
		panic(err)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	if isLoggedIn(r) {
		http.Redirect(w, r, "/welcome", http.StatusSeeOther)
		return
	}

	// const http.MethodPost untyped string = "POST"
	if r.Method == http.MethodPost {
		// FormValue returns the first value for the named component of the query.
		// func (*http.Request).FormValue(key string) string
		email := r.FormValue("email")
		password := r.FormValue("password")

		user := user{}

		// QueryRow executes a query that is expected to return at most one row.
		// func (*sql.DB).QueryRow(query string, args ...interface{}) *sql.Row
		row := db.QueryRow("SELECT * FROM cms_user WHERE email = $1;", email)

		// Scan copies the columns from the matched row into the values pointed at by dest.
		// func (*sql.Row).Scan(dest ...interface{}) error
		err := row.Scan(&user.ID, &user.Firstname, &user.Lastname, &user.Email, &user.Password, &user.ProfilePic, &user.Active, &user.JoinedDate, &user.LastActive)
		if err == sql.ErrNoRows {
			panic(err)
		}

		// CompareHashAndPassword compares a bcrypt hashed password with its possible plaintext equivalent. Returns nil on success, or an error on failure.
		// func bcrypt.CompareHashAndPassword(hashedPassword []byte, password []byte) error
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			panic(err)
		}

		// NewV4 returns random generated UUID.
		// func uuid.NewV4() uuid.UUID
		SID := uuid.NewV4()

		// A Cookie represents an HTTP cookie as sent in the Set-Cookie header of an HTTP response or the Cookie header of an HTTP request.
		c := &http.Cookie{
			Name:     "SID",
			Value:    SID.String(),
			HttpOnly: true,
		}

		// SetCookie adds a Set-Cookie header to the provided ResponseWriter's headers. The provided cookie must have a valid Name. Invalid cookies may be silently dropped.
		// func http.SetCookie(w http.ResponseWriter, cookie *http.Cookie)
		http.SetCookie(w, c)

		dbSessions[c.Value] = email

		http.Redirect(w, r, "/welcome", http.StatusSeeOther)
		return
	}
	err := tpl.ExecuteTemplate(w, "login.html", nil)
	if err != nil {
		// The panic built-in function stops normal execution of the current goroutine
		panic(err)
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	if !isLoggedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	c, err := r.Cookie("SID")
	if err != nil {
		panic(err)
	}

	// The delete built-in function deletes the element with the specified key (m[key]) from the map. If m is nil or there is no such element, delete is a no-op.
	// func(m map[Type]Type1, key Type)
	delete(dbSessions, c.Value)

	c = &http.Cookie{
		Name:     "SID",
		Value:    "",
		HttpOnly: true,
	}
	http.SetCookie(w, c)

	http.Redirect(w, r, "/", http.StatusSeeOther)
	return
}

func signup(w http.ResponseWriter, r *http.Request) {
	if isLoggedIn(r) {
		http.Redirect(w, r, "/welcome", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		Firstname := r.FormValue("Firstname")
		Lastname := r.FormValue("Lastname")
		email := r.FormValue("email")
		password := r.FormValue("password")

		var err error
		var encryptedPassword []byte
		// GenerateFromPassword returns the bcrypt hash of the password at the given cost.
		// func bcrypt.GenerateFromPassword(password []byte, cost int) ([]byte, error)
		encryptedPassword, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			panic(err)
		}

		var user user
		row := db.QueryRow("SELECT * FROM cms_user WHERE email = $1;", email)
		err = row.Scan(&user.ID, &user.Firstname, &user.Lastname, &user.Email, &user.Password, &user.ProfilePic,
			&user.Active, &user.JoinedDate, &user.LastActive)
		if err != sql.ErrNoRows {
			// Fprintf formats according to a format specifier and writes to w. It returns the number of bytes written and any write error encountered.
			// func fmt.Fprintf(w io.Writer, format string, a ...interface{}) (n int, err error)
			fmt.Fprintf(w, "%v already exists", user.Firstname)
		}

		// Exec executes a query without returning any rows. The args are for any placeholder parameters in the query.
		// func (*sql.DB).Exec(query string, args ...interface{}) (sql.Result, error)
		_, err = db.Exec("INSERT INTO cms_user (Firstname, Lastname, email, password, profile_pic, Active, "+
			"joined_date, last_Active) VALUES ($1, "+
			"$2, $3, $4, $5, $6, $7, $8);",
			Firstname, Lastname, email, encryptedPassword, "3ce03cb82293dd0b17029bb64692f134a3f406db.png", true, time.Now(), time.Now())
		if err != nil {
			panic(err)
		}

		SID := uuid.NewV4()

		c := &http.Cookie{
			Name:     "SID",
			Value:    SID.String(),
			HttpOnly: true,
		}

		http.SetCookie(w, c)

		dbSessions[c.Value] = email

		http.Redirect(w, r, "/welcome", http.StatusSeeOther)
		return
	}
	err := tpl.ExecuteTemplate(w, "signup.html", "Click to go back to homepage")
	if err != nil {
		panic(err)
	}
}

func welcome(w http.ResponseWriter, r *http.Request) {
	if !isLoggedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	c, err := r.Cookie("SID")
	if err != nil {
		panic("Cookie not found")
	}

	var user user
	row := db.QueryRow("SELECT * FROM cms_user WHERE email = $1;", dbSessions[c.Value])
	err = row.Scan(&user.ID, &user.Firstname, &user.Lastname, &user.Email, &user.Password, &user.ProfilePic, &user.Active, &user.JoinedDate, &user.LastActive)
	if err != nil {
		panic(err)
	}

	err = tpl.ExecuteTemplate(w, "welcome.html", user)
	if err != nil {
		panic(err)
	}
}

func isLoggedIn(r *http.Request) bool {
	c, err := r.Cookie("SID")
	if err != nil {
		return false
	}

	if _, ok := dbSessions[c.Value]; ok {
		return true
	}
	return false
}

func upload(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("SID")
	if err != nil {
		SID := uuid.NewV4()
		cookie := &http.Cookie{
			Name:     "SID",
			Value:    SID.String(),
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
	}

	if r.Method == http.MethodPost {
		// FormFile returns the first file for the provided form key. FormFile calls ParseMultipartForm and ParseForm if necessary.
		// func (*http.Request).FormFile(key string) (multipart.File, *multipart.FileHeader, error)
		myFile, myFileHeader, err := r.FormFile("myFile")
		if err != nil {
			panic(err)
		}
		defer myFile.Close()

		// Split slices s into all substrings separated by sep and returns a slice of the substrings between those separators.
		// func strings.Split(s string, sep string) []string
		extension := strings.Split(myFileHeader.Filename, ".")[1]

		// New returns a new hash.Hash computing the SHA1 checksum. The Hash also implements encoding.BinaryMarshaler and encoding.BinaryUnmarshaler to marshal and unmarshal the internal state of the hash.
		// func sha1.New() hash.Hash
		newHash := sha1.New()

		// Copy copies from src to dst until either EOF is reached on src or an error occurs.
		// func io.Copy(dst io.Writer, src io.Reader) (written int64, err error)
		io.Copy(newHash, myFile)

		// Sprintf formats according to a format specifier and returns the resulting string.
		// func fmt.Sprintf(format string, a ...interface{}) string
		myFileName := fmt.Sprintf("%x", newHash.Sum(nil)) + "." + extension

		// Getwd returns a rooted path name corresponding to the current directory. If the current directory can be reached via multiple paths (due to symbolic links), Getwd may return any one of them.
		// func os.Getwd() (dir string, err error)
		workingDirectory, err := os.Getwd()
		if err != nil {
			panic(err)
		}

		// Join joins any number of path elements into a single path, separating them with an OS specific Separator.
		// func filepath.Join(elem ...string) string
		path := filepath.Join(workingDirectory, "public", "pics", myFileName)

		// Create creates or truncates the named file. If the file already exists, it is truncated.
		// func os.Create(name string) (*os.File, error)
		myNewFile, err := os.Create(path)
		if err != nil {
			panic(err)
		}

		// func os.Create(name string) (*os.File, error)
		// func (*os.File).Close() error
		defer myNewFile.Close()

		// func (io.Seeker).Seek(offset int64, whence int) (int64, error)
		myFile.Seek(0, 0)

		io.Copy(myNewFile, myFile)

		str := c.Value
		// Contains reports whether substr is within s.
		// func strings.Contains(s string, substr string) bool
		if !strings.Contains(str, myFileName) {
			str += "|" + myFileName
		}

		c.Value = str
		http.SetCookie(w, c)
	}
	splitStrings := strings.Split(c.Value, "|")
	err = tpl.ExecuteTemplate(w, "upload.html", splitStrings[1:])
	if err != nil {
		panic(err)
	}
}
