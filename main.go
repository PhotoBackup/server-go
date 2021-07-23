//
// This is a small HTTP server implementing the "photobackup server" endpoint
// documented here: https://github.com/PhotoBackup/api/
//
// Written because the existing servers make me a touch sad; go means we can
// avoid a pile of runtime dependencies. Build-time dependencies are being kept
// low; bcrypt, homedir and graceful are the only luxuries. Adding gorilla mux
// and, perhaps, negroni, would probably be overkill.
//
// We're trying to be compatible, so config file is INI-format: ~/.photobackup
// 	   [photobackup]
// 	   MediaRoot=<path to store files in>
//	   Password=<sha512 digest of password, no salt>
//	   Port=<port>
//
// In addition to these keys, I'm also supporting:
// 	   BindAddress=<address to bind to>
// 	   PasswordBcrypt=<bcrypt of sha512 digest of plain password>
// 	   HTTPPrefix=<prefix to mount HTTP server at>
//
// The original server was intended to run over HTTP, I think, hence the client
// sending a SHA512'd password. We support this scheme, but the on-disc storage
// format is really better off being bcrypt(sha512(password)), so I've added
// that.
//
// Adding BindAddress and HTTPPrefix means that mounting this behind a HTTP
// reverse proxy is quite doable, and lets us offload HTTPS to that as well.
// That's how I'm intending to use it.
//
// I think the original servers are designed so you can connect to them using
// just HTTP; hence the sha512(password) scheme. This is short-sighted; the only
// thing it gets you is (weak) protection against sniffing if you happen to use
// the same password elsewhere. Sniffers in this scenario can still upload to
// your server and view your photos.
//
// At some point in the future I might add direct HTTPS support as well, but I
// don't need it.
//
// @author Nick Thomas <photobackup@ur.gs>
package main

import (
	"errors"
	"fmt"
	"github.com/Unknwon/goconfig"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/tylerb/graceful.v1"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Config struct {
	MediaRoot      string // mandatory
	Port           string // optional, defaults to 8420
	BindAddress    string // Optional, defaults to 127.0.0.1
	PasswordBcrypt string // Either this or Password
	HTTPPrefix     string // Optional, defaults to "/"
}

// Implements the API defined here: https://github.com/PhotoBackup/api
type Handler struct {
	Config *Config
}

func (h *Handler) BuildMux() http.Handler {
	mux := http.NewServeMux()

	prefix := h.Config.HTTPPrefix
	if prefix == "/" {
		prefix = ""
	}

	// We don't use http.StripPrefix because that leaves a path of "" for "/foo"
	if len(prefix) > 0 {
		mux.HandleFunc(prefix, h.RootHandler)
	}

	mux.HandleFunc(prefix+"/", h.RootHandler)

	mux.HandleFunc(prefix+"/test", h.TestHandler)
	mux.HandleFunc(prefix+"/test/", h.TestHandler)

	return mux
}

// TODO: this lot could be refactored into smaller methods
func (h *Handler) RootHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		http.Redirect(w, r, "https://photobackup.github.io/", 302)
		return
	}

	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	if !h.CheckPassword(w, r) {
		return
	}

	filesize, ok := h.ReadFileSize(w, r)
	if !ok {
		return
	}

	upfile, upfileHdr, err := r.FormFile("upfile")
	if upfile == nil || upfileHdr == nil || upfileHdr.Filename == "" || err != nil {
		if err == nil {
			err = errors.New("Unknown error")
		}

		// No idea why the spec demands 401 here
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Failed to read upfile parameter: " + err.Error()))

		return
	}

	filename := filepath.Join(h.Config.MediaRoot, upfileHdr.Filename)

	// Create the file with O_EXCL so that we can detect if the file
	// already exists and return a 409 if it does. This isn't in the RAML,
	// and the "official" Python API returns nothing AFAICT. This is
	// definitely an improvement over that!
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		if os.IsExist(err) {
			w.WriteHeader(http.StatusConflict)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		w.Write([]byte("Error opening file: " + err.Error()))
		return
	}

	// Try to read `filesize` bytes into the destination. An io.EOF says
	// that filesize was too low; anything else was our fault.
	_, err = io.CopyN(file, upfile, filesize)

	if err != nil {
		if err == io.EOF {
			w.WriteHeader(http.StatusLengthRequired)
			w.Write([]byte("filesize larger than upfile data"))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error writing file: " + err.Error()))
		}

		// best-effort `rm' here.
		_ = os.Remove(filename)

		return
	}

	// Now we try to read one more byte. If that *doesn't* return EOF, then
	// filesize was too low.
	//
	// What we don't do here is read the entire file before deciding that
	// it was too big, as the Python server does.
	tmp := make([]byte, 1)
	if _, err := upfile.Read(tmp); err == nil {
		w.WriteHeader(http.StatusLengthRequired)
		w.Write([]byte("upfile data larger than filesize"))

		// best-effort remove here too
		_ = os.Remove(filename)

		return
	}

	if err := file.Close(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error closing written file: " + err.Error()))
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) TestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	if !h.CheckPassword(w, r) {
		return
	}

	filename := filepath.Join(h.Config.MediaRoot, ".test_file_to_write")
	_ = os.Remove(filename)
	defer os.Remove(filename)

	file, err := os.Create(filename)
	if err == nil {
		err = file.Close()
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error opening file: " + err.Error()))
		return
	}
}

// The multipart/mime form-data "password" the hexdigested sha512'd password
// We bcrypt() it then check it against the password in the config file in a
// way that *isn't* vulnerable to timing attacks.
//
// Side effect: We write a 403 to w if the password is bad or missing
func (h *Handler) CheckPassword(w http.ResponseWriter, r *http.Request) bool {
	// TODO: get rid of these conversions
	actual := []byte(h.Config.PasswordBcrypt)
	putative := []byte(r.FormValue("password"))
	ok := (bcrypt.CompareHashAndPassword(actual, putative) == nil)

	if !ok {
		w.WriteHeader(http.StatusForbidden)
	}

	return ok
}

// Reads the filesize parameter from the request.
//
// Side effect: Writes a 400 if the filesize param isn't present or doesn't
// convert to a positive int64. The spec allows the client to specify a negative
// number but I'm not interested in that.
func (h *Handler) ReadFileSize(w http.ResponseWriter, r *http.Request) (int64, bool) {
	str := r.FormValue("filesize")
	if str == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("filesize not set"))
		return -1, false
	}

	filesize, err := strconv.ParseInt(str, 10, 64)
	if err != nil || filesize < 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("filesize does not parse to a 64-bit int > 0"))
		return -1, false
	}

	return filesize, true
}

func GetConfig() (*Config, error) {
	var ConfigFile string

	if len(os.Args) == 2 {
		ConfigFile = os.Args[1]
	} else {
		if base, err := homedir.Dir(); err != nil {
			return nil, err
		} else {
			ConfigFile = filepath.Join(base, ".photobackup")
		}
	}

	cfg, err := goconfig.LoadConfigFile(ConfigFile)
	if err != nil {
		return nil, err
	}
	section, err := cfg.GetSection("photobackup")
	if err != nil {
		return nil, err
	}

	out := Config{
		MediaRoot:      section["MediaRoot"],
		Port:           section["Port"],
		BindAddress:    section["BindAddress"],
		PasswordBcrypt: section["PasswordBcrypt"],
		HTTPPrefix:     section["HTTPPrefix"],
	}

	if out.MediaRoot == "" {
		return nil, errors.New("MediaRoot not specified")
	}
	// TODO: check MediaRoot is a valid, writable path?

	// If Password and PasswordBcrypt are both set, the latter wins
	if pwd, ok := section["Password"]; ok && out.PasswordBcrypt == "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
		if err != nil {
			return nil, errors.New("Failed to convert Password to PasswordBcrypt: " + err.Error())
		}
		out.PasswordBcrypt = string(hash)
	}

	if out.PasswordBcrypt == "" {
		return nil, errors.New("Neither Password nor PasswordBcrypt specified")
	}

	if out.BindAddress == "" {
		out.BindAddress = "127.0.0.1"
	}

	if out.Port == "" {
		out.Port = "8420"
	}

	return &out, nil
}

func main() {

	if len(os.Args) > 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [config-file]\n", os.Args[0])
		os.Exit(1)
	}

	config, err := GetConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't read config: %s\n", err.Error())
		os.Exit(1)
	}

	listenOn := net.JoinHostPort(config.BindAddress, config.Port)
	api := &Handler{Config: config}
	mux := api.BuildMux()

	graceful.Run(listenOn, 10*time.Second, mux)
}
