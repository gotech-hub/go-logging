package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
)

// TraceInfo contains trace information for a request.
type TraceInfo struct {
	RequestID string `json:"request_id"`
}

// GetFullStack returns the file and function information from the current stacktrace.
func GetFullStack() string {
	buf := make([]byte, 1<<16)
	stackSize := runtime.Stack(buf, true)
	stack := fmt.Sprintf("%s", buf[0:stackSize])
	stackTemp := strings.Split(stack, "\n")
	if len(stackTemp) > 6 {
		stackFile := fmt.Sprintf("file: %s, func: %s", strings.TrimSpace(stackTemp[6]), strings.TrimSpace(stackTemp[5]))
		return stackFile
	}
	return "stacktrace unavailable"
}

// AnyToString converts any value to a string. If the value is a string or []byte, it returns it directly; otherwise, it marshals the value to JSON.
func AnyToString(value any) (string, error) {
	if value == nil {
		return "", nil
	}

	if str, ok := value.(string); ok {
		return str, nil
	}

	if str, ok := value.([]byte); ok {
		return string(str), nil
	}

	byteValue, err := json.Marshal(value)
	if err != nil {
		return "", err
	}

	return string(byteValue), nil
}

// GetRequestIdByContext retrieves TraceInfo from the context, returns nil if not found or wrong type.
func GetRequestIdByContext(ctx context.Context) *TraceInfo {
	value := ctx.Value(KeyTraceInfo)
	traceInfo, ok := value.(TraceInfo)
	if !ok {
		return nil
	}
	return &traceInfo
}

func EncryptLog[T any](data T) (T, error) {
	if keyEncrypt == nil || *keyEncrypt == "" {
		return data, nil
	}

	switch v := interface{}(data).(type) {
	case string:
		res, err := Encrypt(v, *keyEncrypt)
		if err != nil {
			return data, err
		}

		var result interface{} = res
		return result.(T), nil
	case *string:
		res, err := Encrypt(*v, *keyEncrypt)
		if err != nil {
			return data, err
		}

		var result interface{} = &res
		return result.(T), nil
	}

	return InterfaceEncryptTag(data, *keyEncrypt, TagNameEncrypt, TagValEncrypt)
}

func EncryptInterface(data interface{}) (interface{}, error) {
	if keyEncrypt == nil || *keyEncrypt == "" {
		return data, nil
	}

	switch v := data.(type) {
	case string:
		return Encrypt(v, *keyEncrypt)
	case *string:
		return Encrypt(*v, *keyEncrypt)
	}

	return InterfaceEncryptTagInterface(data, *keyEncrypt, TagNameEncrypt, TagValEncrypt)
}
