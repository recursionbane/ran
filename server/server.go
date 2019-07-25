package server

import "fmt"
import "errors"
import "net/http"
import "os"
import "time"
import "math/rand"
import "path/filepath"
import "crypto/md5"
import "github.com/m3ng9i/go-utils/log"
import hhelper "github.com/m3ng9i/go-utils/http"

// For user -> group validation
import "os/user"
import "syscall"

// import "reflect"

// For JWT validation
import "strings"
import "encoding/json"
import "github.com/dgrijalva/jwt-go"

// print the contents of the obj
func PrettyPrint(data interface{}) {
	var p []byte
	//    var err := error
	p, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s \n", p)
}

func IsInList(arr []string, str string) bool {
	// Does the specifies array contain the specified string element?
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

func CanUserAccessFile(username string, abspath string) bool {
	// Check if a given username belongs to a group that can read the supplied abspath file's contents based on its primary group
	// Compare requested file's group ID (gid) and check against specified username's groups to see if user should be able to read this file
	file_info, _ := os.Stat(abspath)
	file_sys := file_info.Sys()
	// fmt.Println(reflect.ValueOf(file_sys))
	file_gid := fmt.Sprint(file_sys.(*syscall.Stat_t).Gid) // As a string

	// fmt.Println(username + " is attempting to access " + abspath + " which has gid " + file_gid)

	// Map username to User struct
	r_user_obj, _ := user.Lookup(username)
	r_user_groups, _ := r_user_obj.GroupIds()

	return IsInList(r_user_groups, file_gid)
}

// serveFile() serve any request with content pointed by abspath.
func serveFile(w http.ResponseWriter, r *http.Request, abspath string) error {
	f, err := os.Open(abspath)
	if err != nil {
		return err
	}

	info, err := f.Stat()
	if err != nil {
		return err
	}

	if info.IsDir() {
		return errors.New("Cannot serve content of a directory")
	}

	filename := info.Name()

	// Check the incoming request headers to make sure an "id_token" cookie exists
	cookie, _ := r.Cookie("id_token")
	tokenString := cookie.Value

	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	// Validate id_token as a JWT to ensure integrity is not compromised
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return token, nil
	})

	// TODO: Validate id_token against an external service to ensure it's not spoofed
	claims, _ := token.Claims.(jwt.MapClaims)
	splitter := strings.Split(fmt.Sprintf("%v", claims["upn"]), "@")
	r_username := splitter[0]

	// Check if user is part of at least one group that can read this file
	if CanUserAccessFile(r_username, abspath) {
		// fmt.Println("User can access file!")
		// Proceed
	} else {
		fmt.Println(r_username + " cannot access file " + abspath)
		// Do not serve the file
		return nil
	}

	// temp, _ := json.Marshal(info.Sys())
	// file_gid, _ := temp["Gid"]
	// PrettyPrint(temp)
	// PrettyPrint(token.Claims)

	// TODO if client (use JavaScript) send a request head: 'Accept: "application/octet-stream"' then write the download header ?
	// if the url contains a query like "?download", then download this file
	_, ok := r.URL.Query()["download"]
	if ok {
		hhelper.WriteDownloadHeader(w, filename)
	}

	// http.ServeContent() always return a status code of 200.

	http.ServeContent(w, r, filename, info.ModTime(), f)
	return nil
}

type RanServer struct {
	config Config
	logger *log.Logger
}

func NewRanServer(c Config, logger *log.Logger) *RanServer {
	return &RanServer{
		config: c,
		logger: logger,
	}
}

func (this *RanServer) serveHTTP(w http.ResponseWriter, r *http.Request) {

	requestId := string(getRequestId(r.URL.String()))

	w.Header().Set("X-Request-Id", requestId)
	// WARNING - ONLY USE BEHIND TRUSTED NETWORKS
	// Allow requests from anywhere
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	this.logger.Debugf("#%s: r.URL: [%s]", requestId, r.URL.String())

	context, err := newContext(this.config, r)
	if err != nil {
		Error(w, 500)
		this.logger.Errorf("#%s: %s", requestId, err)
		return
	}

	this.logger.Debugf("#%s: Context: [%s]", requestId, context.String())

	// redirect to a clean url
	if r.URL.String() != context.url {
		http.Redirect(w, r, context.url, http.StatusTemporaryRedirect)
		return
	}

	// display 404 error
	if !context.exist {
		if this.config.Path404 != nil {
			_, err = ErrorFile404(w, *this.config.Path404)
			if err != nil {
				this.logger.Errorf("#%s: Load 404 file error: %s", requestId, err)
				Error(w, 404)
			}
		} else {
			Error(w, 404)
		}
		return
	}

	// display index page
	if context.indexPath != "" {
		err := serveFile(w, r, context.absFilePath)
		if err != nil {
			Error(w, 500)
			this.logger.Errorf("#%s: %s", requestId, err)
		}
		return
	}

	// display directory list.
	// if c.isDir is true, Config.ListDir must be true,
	// so there is no need to check value of Config.ListDir.
	if context.isDir {
		// display file list of a directory
		_, err = this.listDir(w, this.config.ServeAll, context)
		if err != nil {
			Error(w, 500)
			this.logger.Errorf("#%s: %s", requestId, err)
		}
		return
	}

	// serve the static file only if its extension is not in the ignore list
	// Check if the extension of this file is in the ignore list
	ext := filepath.Ext(context.absFilePath)
	if isStringInCSV(ext, context.ignorefileext) {
		// Do not serve the file
		this.logger.Errorf("Not serving file '%s' because its extension '%s' is in list of ignorefilext [%s]", context.absFilePath, ext, context.ignorefileext)
		Error(w, 404)
	} else {
		// Actually attempt serve the file
		err = serveFile(w, r, context.absFilePath)
		if err != nil {
			Error(w, 500)
			this.logger.Errorf("#%s: %s", requestId, err)
			return
		}
	}

	return
}

// generate a random number in [300,2499], set n for more randomly number
func randTime(n ...int64) int {

	i := time.Now().Unix()
	if len(n) > 0 {
		i += n[0]
	}
	if i < 0 {
		i = 1
	}

	rand.Seed(i)
	return rand.Intn(2200) + 300 // [300,2499]
}

// make the request handler chain:
// log -> authentication -> gzip -> original handler
// TODO: add ip filter: log -> [ip filter] -> authentication -> gzip -> original handler
func (this *RanServer) Serve() http.HandlerFunc {

	// original ran server handler
	handler := this.serveHTTP

	// gzip handler
	if this.config.Gzip {
		handler = hhelper.GzipHandler(handler, true, true)
	}

	// authentication handler
	if this.config.Auth != nil {
		realm := "Identity authentication"

		failFunc := func() {
			// sleep 300~2499 milliseconds to prevent brute force attack
			time.Sleep(time.Duration(randTime()) * time.Millisecond)
		}

		var authFile *hhelper.AuthFile

		// load custom 401 file
		if this.config.Path401 != nil {
			var err error
			authFile, err = errorFile401(this.config)
			if err != nil {
				this.logger.Errorf("Load 401 file error: %s", err)
			}
		}

		if this.config.Auth.Method == DigestMethod {
			da := hhelper.DigestAuth{
				Realm: realm,

				Secret: func(user, realm string) string {
					if user == this.config.Auth.Username {
						md5sum := md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", user, realm, this.config.Auth.Password)))
						return fmt.Sprintf("%x", md5sum)
					}
					return ""
				},

				ClientCacheSize:      2000,
				ClientCacheTolerance: 200,
			}

			// if authFile is nil, display the default 401 error message
			handler = da.DigestAuthHandler(handler, authFile, failFunc)
		} else {
			ba := hhelper.BasicAuth{
				Realm:  realm,
				Secret: hhelper.BasicAuthSecret(this.config.Auth.Username, this.config.Auth.Password),
			}

			handler = ba.BasicAuthHandler(handler, authFile, failFunc)
		}
	}

	// log handler
	handler = this.logHandler(handler)

	return func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)
	}
}

// redirect to https page
func (this *RanServer) RedirectToHTTPS(port uint) http.HandlerFunc {
	handler := this.logHandler(hhelper.RedirectToHTTPS(port))
	return func(w http.ResponseWriter, r *http.Request) {
		requestId := string(getRequestId(r.URL.String()))
		w.Header().Set("X-Request-Id", requestId)
		handler(w, r)
	}
}
