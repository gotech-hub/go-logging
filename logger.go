package logger

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"strings"
	"sync"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
)

// Global logger instance and encryption key
var (
	loggerInstance *Logger
	mu             sync.RWMutex
	keyEncrypt     *string
)

// Common constants
const (
	KeyServiceName = "service_name"
	KeyFileError   = "file_error"
)

// Logger is the main struct for logging, wrapping zerolog.Logger.
type Logger struct {
	logger zerolog.Logger
}

// InitLog initializes the global logger instance with the given service name.
func InitLog(serviceName string) {
	mu.Lock()
	defer mu.Unlock()
	if loggerInstance != nil {
		return
	}

	if serviceName == "" {
		log.Fatal().Msg("services name is empty")
	}

	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	lg := log.With().Str(KeyServiceName, serviceName).Logger()
	loggerInstance = &Logger{lg}
}

// SetKeyEncrypt sets the encryption key for logging.
func SetKeyEncrypt(key string) {
	if keyEncrypt == nil {
		keyEncrypt = &key
	}
}

// GetLogger returns the global logger instance.
func GetLogger() *Logger {
	return loggerInstance
}

// SetEchoReqEncrLog encrypts and sets the request body in Echo context for logging.
func SetEchoReqEncrLog(c echo.Context, req interface{}) {
	if keyEncrypt == nil || *keyEncrypt == "" {
		return
	}

	ctx := c.Request().Context()
	if req != nil {
		if newReq, err := StructEncryptTagInterface(req, *keyEncrypt, TagNameEncrypt, TagValEncrypt); err == nil {
			if str, err := AnyToString(newReq); err == nil {
				ctx = context.WithValue(ctx, KeyRequestBody, str)
				c.SetRequest(c.Request().WithContext(ctx))
			}
		}
	}
}

// SetEchoRespEncrLog encrypts and sets the response body in Echo context for logging.
func SetEchoRespEncrLog(c echo.Context, resp interface{}) {
	if keyEncrypt == nil || *keyEncrypt == "" {
		return
	}

	ctx := c.Request().Context()

	// check response is nil
	if resp == nil {
		return
	}

	v := reflect.ValueOf(resp)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	// get value field Data from response
	if v.Kind() == reflect.Struct {
		if data := v.FieldByName("Data"); data.IsValid() {
			if data.Kind() == reflect.Ptr {
				data = data.Elem()
			}

			if newRes, err := InterfaceEncryptTagInterface(data.Interface(), *keyEncrypt, TagNameEncrypt, TagValEncrypt); err == nil {
				if str, err := AnyToString(newRes); err == nil {
					ctx = context.WithValue(ctx, KeyResponseBody, str)
					c.SetRequest(c.Request().WithContext(ctx))
				}
			}
		}
	}
}

// ------------------- Logger -------------------

// StackTrace adds stacktrace information to the logger and returns a new logger.
func (l *Logger) StackTrace() *Logger {
	stack := GetFullStack()
	newLg := l.logger.With().Str(KeyFileError, stack).Logger()
	return &Logger{newLg}
}

// AddTraceInfoContextRequest adds trace and caller information from context to the logger.
func (l *Logger) AddTraceInfoContextRequest(ctx context.Context) *Logger {
	newLg := l.logger.With().Interface("caller", l.GetCaller()).Logger()
	traceInfo := GetRequestIdByContext(ctx)
	if traceInfo != nil {
		newLg = newLg.With().Interface(KeyTraceInfo, traceInfo).Logger()
	}
	return &Logger{newLg}
}

// Output returns a new logger that writes to writer w.
func (l Logger) Output(w io.Writer) Logger {
	return Logger{l.logger.Output(w)}
}

// Level returns a new logger with the specified level.
func (l Logger) Level(lvl zerolog.Level) Logger {
	return Logger{l.logger.Level(lvl)}
}

// Sample returns a new logger with the specified sampler.
func (l Logger) Sample(s zerolog.Sampler) Logger {
	return Logger{l.logger.Sample(s)}
}

// Hook returns a new logger with the specified hooks.
func (l Logger) Hook(hooks ...zerolog.Hook) Logger {
	return Logger{l.logger.Hook(hooks...)}
}

// ------------------- Logger -------------------

// ------------------- Context -------------------

// With returns a Context to build a log event with additional fields.
func (l Logger) With() Context {
	return Context{l: l}
}

// ------------------- Context -------------------

// ------------------- context.Context -------------------

// WithContext returns a context containing this logger.
func (l Logger) WithContext(ctx context.Context) context.Context {
	return l.logger.WithContext(ctx)
}

// ------------------- context.Context -------------------

// ------------------- Event -------------------

// Trace creates a log event at Trace level.
func (l *Logger) Trace() *Event {
	return &Event{l.logger.Trace()}
}

// Debug creates a log event at Debug level.
func (l *Logger) Debug() *Event {
	return &Event{l.logger.Debug()}
}

// Info creates a log event at Info level.
func (l *Logger) Info() *Event {
	return &Event{l.logger.Info()}
}

// Warn creates a log event at Warn level.
func (l *Logger) Warn() *Event {
	return &Event{l.logger.Warn()}
}

// Error creates a log event at Error level.
func (l *Logger) Error() *Event {
	return &Event{l.logger.Error()}
}

// Err creates a log event with the provided error.
func (l *Logger) Err(err error) *Event {
	return &Event{l.logger.Err(err)}
}

// Fatal creates a log event at Fatal level.
func (l *Logger) Fatal() *Event {
	return &Event{l.logger.Fatal()}
}

// Panic creates a log event at Panic level.
func (l *Logger) Panic() *Event {
	return &Event{l.logger.Panic()}
}

// WithLevel creates a log event with the specified level.
func (l *Logger) WithLevel(level zerolog.Level) *Event {
	return &Event{l.logger.WithLevel(level)}
}

// Log creates a default log event.
func (l *Logger) Log() *Event {
	return &Event{l.logger.Log()}
}

// ------------------- Event -------------------

// ------------------- Extend -------------------

// GetCaller returns the file, line, and function information of the logger caller.
func (l *Logger) GetCaller() string {
	pc, file, line, ok := runtime.Caller(2) // Adjust the call stack index as needed
	if !ok {
		return ""
	}

	fullFnName := runtime.FuncForPC(pc).Name()
	parts := strings.Split(fullFnName, ".")
	fnName := parts[len(parts)-1]

	return fmt.Sprintf("%s:%d %s", file, line, fnName)
}

// GetLevel returns the current log level of the logger.
func (l Logger) GetLevel() zerolog.Level {
	return l.logger.GetLevel()
}

// Write writes a log as []byte.
func (l Logger) Write(p []byte) (n int, err error) {
	return l.logger.Write(p)
}

// UpdateContext updates the logger's context.
func (l *Logger) UpdateContext(update func(c zerolog.Context) zerolog.Context) {
	l.logger.UpdateContext(update)
}

// Print writes a log using Print.
func (l *Logger) Print(v ...interface{}) {
	l.logger.Print(v...)
}

// Printf writes a log using Printf.
func (l *Logger) Printf(format string, v ...interface{}) {
	l.logger.Printf(format, v...)
}

// Println writes a log using Println.
func (l *Logger) Println(v ...interface{}) {
	l.logger.Println(v...)
}
