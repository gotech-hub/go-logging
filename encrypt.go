package logger

import (
	"fmt"
	"reflect"
)

// StructEncryptTag encrypts fields of a struct based on the tag `tagName:"tagVal"`.
// It returns a new struct with encrypted fields or an error if encryption fails.
func StructEncryptTag[T any](input T, key, tagName, tagVal string) (T, error) {
	if key == "" {
		return input, nil
	}

	// deep copy input
	inputCopy := Copy(input)

	v := reflect.ValueOf(inputCopy)

	var isPtr bool
	if v.Type().Kind() == reflect.Ptr {
		v = v.Elem()
		isPtr = true
	}

	t := v.Type()

	// check if input is a struct
	if t.Kind() != reflect.Struct {
		return input, fmt.Errorf("input is not a struct")
	}

	output := reflect.New(t).Elem()

	// Copy the values from input to output
	output.Set(v)

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)

		// check field type is time.Time
		if field.Kind() == reflect.Struct && field.Type().String() == "time.Time" {
			continue
		}

		// check field type is *time.Time
		if field.Kind() == reflect.Ptr && field.Elem().Kind() == reflect.Struct && field.Elem().Type().String() == "time.Time" {
			continue
		}

		tag := t.Field(i).Tag.Get(tagName)

		if tag == tagVal && field.Kind() == reflect.String {
			encryptedValue, err := Encrypt(field.String(), key)
			if err != nil {
				return input, err
			}
			output.Field(i).SetString(encryptedValue)
			continue
		}

		if tag == tagVal && (field.Kind() == reflect.Ptr && field.Elem().Kind() == reflect.String) {
			encryptedValue, err := Encrypt(field.Elem().String(), key)
			if err != nil {
				return input, err
			}
			output.Field(i).Elem().Set(reflect.ValueOf(encryptedValue))
			continue
		}

		if field.Kind() == reflect.Struct {
			encryptedField, err := StructEncryptTag(field.Interface(), key, tagName, tagVal)
			if err != nil {
				return input, err
			}
			output.Field(i).Set(reflect.ValueOf(encryptedField))
			continue
		}

		if field.Kind() == reflect.Ptr && field.Elem().Kind() == reflect.Struct {
			encryptedField, err := StructEncryptTag(field.Elem().Interface(), key, tagName, tagVal)
			if err != nil {
				return input, err
			}
			output.Field(i).Elem().Set(reflect.ValueOf(encryptedField))
		}
	}

	if isPtr {
		return output.Addr().Interface().(T), nil
	}

	return output.Interface().(T), nil
}

// StructSliceEncryptTag encrypts fields of a slice of struct based on the tag `tagName:"tagVal"`.
// It returns a new slice with encrypted fields or an error if encryption fails.
func StructSliceEncryptTag[T any](input T, key, tagName, tagVal string) (T, error) {
	if key == "" {
		return input, nil
	}

	// deep copy input
	inputCopy := Copy(input)

	v := reflect.ValueOf(inputCopy)

	if v.Kind() != reflect.Slice {
		return input, fmt.Errorf("input is not a slice")
	}

	for i := 0; i < v.Len(); i++ {
		item := v.Index(i)

		// check if item is a struct
		if item.Kind() == reflect.Struct {
			encryptedItem, err := StructEncryptTag(item.Interface(), key, tagName, tagVal)
			if err != nil {
				return input, err
			}
			v.Index(i).Set(reflect.ValueOf(encryptedItem))
			continue
		}

		// check if item is a pointer struct
		if item.Kind() == reflect.Ptr && item.Elem().Kind() == reflect.Struct {
			encryptedItem, err := StructEncryptTag(item.Interface(), key, tagName, tagVal)
			if err != nil {
				return input, err
			}
			v.Index(i).Set(reflect.ValueOf(encryptedItem))
		}
	}

	return v.Interface().(T), nil
}

// InterfaceEncryptTag encrypts fields of a struct, pointer to struct, or slice based on the tag `tagName:"tagVal"`.
// It returns a new value with encrypted fields or an error if encryption fails.
func InterfaceEncryptTag[T any](input T, key, tagName, tagVal string) (T, error) {
	if key == "" {
		return input, nil
	}

	v := reflect.ValueOf(input)

	// check if input is a struct
	if v.Kind() == reflect.Struct {
		if result, err := StructEncryptTag(v.Interface(), key, tagName, tagVal); err != nil {
			return input, err
		} else {
			return result.(T), nil
		}
	}

	// check if item is a pointer struct
	if v.Kind() == reflect.Ptr && v.Elem().Kind() == reflect.Struct {
		if result, err := StructEncryptTag(v.Interface(), key, tagName, tagVal); err != nil {
			return input, err
		} else {
			return result.(T), nil
		}
	}

	// check if input is a slice
	if v.Kind() == reflect.Slice {
		if result, err := StructSliceEncryptTag(v.Interface(), key, tagName, tagVal); err != nil {
			return input, err
		} else {
			return result.(T), nil
		}
	}

	return input, nil
}

// StructDecryptTag decrypts fields of a struct based on the tag `tagName:"tagVal"`.
// It returns a new struct with decrypted fields or an error if decryption fails.
func StructDecryptTag[T any](input T, key, tagName, tagVal string) (T, error) {
	if key == "" {
		return input, nil
	}

	// deep copy input
	inputCopy := Copy(input)

	v := reflect.ValueOf(inputCopy)

	var isPtr bool
	if v.Type().Kind() == reflect.Ptr {
		v = v.Elem()
		isPtr = true
	}

	t := v.Type()

	// check if input is a struct
	if t.Kind() != reflect.Struct {
		return input, fmt.Errorf("input is not a struct")
	}

	output := reflect.New(t).Elem()

	// Copy the values from input to output
	output.Set(v)

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)

		// check field type is time.Time
		if field.Kind() == reflect.Struct && field.Type().String() == "time.Time" {
			continue
		}

		// check field type is *time.Time
		if field.Kind() == reflect.Ptr && field.Elem().Kind() == reflect.Struct && field.Elem().Type().String() == "time.Time" {
			continue
		}

		tag := t.Field(i).Tag.Get(tagName)

		if tag == tagVal && field.Kind() == reflect.String {
			encryptedValue, err := Decrypt(field.String(), key)
			if err != nil {
				return input, err
			}
			output.Field(i).SetString(encryptedValue)
			continue
		}

		if tag == tagVal && (field.Kind() == reflect.Ptr && field.Elem().Kind() == reflect.String) {
			encryptedValue, err := Decrypt(field.Elem().String(), key)
			if err != nil {
				return input, err
			}
			output.Field(i).Elem().Set(reflect.ValueOf(encryptedValue))
			continue
		}

		if field.Kind() == reflect.Struct {
			encryptedField, err := StructDecryptTag(field.Interface(), key, tagName, tagVal)
			if err != nil {
				return input, err
			}
			output.Field(i).Set(reflect.ValueOf(encryptedField))
			continue
		}

		if field.Kind() == reflect.Ptr && field.Elem().Kind() == reflect.Struct {
			encryptedField, err := StructDecryptTag(field.Elem().Interface(), key, tagName, tagVal)
			if err != nil {
				return input, err
			}
			output.Field(i).Elem().Set(reflect.ValueOf(encryptedField))
		}
	}

	if isPtr {
		return output.Addr().Interface().(T), nil
	}

	return output.Interface().(T), nil
}

// StructSliceDecryptTag decrypts fields of a slice of struct based on the tag `tagName:"tagVal"`.
// It returns a new slice with decrypted fields or an error if decryption fails.
func StructSliceDecryptTag[T any](input T, key, tagName, tagVal string) (T, error) {
	if key == "" {
		return input, nil
	}

	// deep copy input
	inputCopy := Copy(input)

	v := reflect.ValueOf(inputCopy)

	if v.Kind() != reflect.Slice {
		return input, fmt.Errorf("input is not a slice")
	}

	for i := 0; i < v.Len(); i++ {
		item := v.Index(i)

		// check if item is a struct
		if item.Kind() == reflect.Struct {
			encryptedItem, err := StructDecryptTag(item.Interface(), key, tagName, tagVal)
			if err != nil {
				return input, err
			}
			v.Index(i).Set(reflect.ValueOf(encryptedItem))
			continue
		}

		// check if item is a pointer struct
		if item.Kind() == reflect.Ptr && item.Elem().Kind() == reflect.Struct {
			encryptedItem, err := StructDecryptTag(item.Interface(), key, tagName, tagVal)
			if err != nil {
				return input, err
			}
			v.Index(i).Set(reflect.ValueOf(encryptedItem))
		}
	}

	return v.Interface().(T), nil
}

// InterfaceDecryptTag decrypts fields of a struct, pointer to struct, or slice based on the tag `tagName:"tagVal"`.
// It returns a new value with decrypted fields or an error if decryption fails.
func InterfaceDecryptTag[T any](input T, key, tagName, tagVal string) (T, error) {
	if key == "" {
		return input, nil
	}

	v := reflect.ValueOf(input)

	// check if input is a struct
	if v.Kind() == reflect.Struct {
		if result, err := StructDecryptTag(v.Interface(), key, tagName, tagVal); err != nil {
			return input, err
		} else {
			return result.(T), nil
		}
	}

	// check if item is a pointer struct
	if v.Kind() == reflect.Ptr && v.Elem().Kind() == reflect.Struct {
		if result, err := StructDecryptTag(v.Interface(), key, tagName, tagVal); err != nil {
			return input, err
		} else {
			return result.(T), nil
		}
	}

	// check if input is a slice
	if v.Kind() == reflect.Slice {
		if result, err := StructSliceDecryptTag(v.Interface(), key, tagName, tagVal); err != nil {
			return input, err
		} else {
			return result.(T), nil
		}
	}

	return input, nil
}

// StructEncryptTagInterface encrypts fields of a struct (interface{}) based on the tag `tagName:"tagVal"`.
// It returns a new struct with encrypted fields or an error if encryption fails.
func StructEncryptTagInterface(input interface{}, key, tagName, tagVal string) (interface{}, error) {
	if key == "" {
		return input, nil
	}

	// deep copy input
	inputCopy := Copy(input)

	v := reflect.ValueOf(inputCopy)

	var isPtr bool
	if v.Type().Kind() == reflect.Ptr {
		v = v.Elem()
		isPtr = true
	}

	t := v.Type()

	// check if input is a struct
	if t.Kind() != reflect.Struct {
		return input, fmt.Errorf("input is not a struct")
	}

	output := reflect.New(t).Elem()

	// Copy the values from input to output
	output.Set(v)

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)

		// check field type is time.Time
		if field.Kind() == reflect.Struct && field.Type().String() == "time.Time" {
			continue
		}

		// check field type is *time.Time
		if field.Kind() == reflect.Ptr && field.Elem().Kind() == reflect.Struct && field.Elem().Type().String() == "time.Time" {
			continue
		}

		tag := t.Field(i).Tag.Get(tagName)

		if tag == tagVal && field.Kind() == reflect.String {
			encryptedValue, err := Encrypt(field.String(), key)
			if err != nil {
				return input, err
			}
			output.Field(i).SetString(encryptedValue)
			continue
		}

		if tag == tagVal && (field.Kind() == reflect.Ptr && field.Elem().Kind() == reflect.String) {
			encryptedValue, err := Encrypt(field.Elem().String(), key)
			if err != nil {
				return input, err
			}
			output.Field(i).Elem().Set(reflect.ValueOf(encryptedValue))
			continue
		}

		if field.Kind() == reflect.Struct {
			encryptedField, err := StructEncryptTagInterface(field.Interface(), key, tagName, tagVal)
			if err != nil {
				return input, err
			}
			output.Field(i).Set(reflect.ValueOf(encryptedField))
			continue
		}

		if field.Kind() == reflect.Ptr && field.Elem().Kind() == reflect.Struct {
			encryptedField, err := StructEncryptTagInterface(field.Elem().Interface(), key, tagName, tagVal)
			if err != nil {
				return input, err
			}
			output.Field(i).Elem().Set(reflect.ValueOf(encryptedField))
		}
	}

	if isPtr {
		return output.Addr().Interface(), nil
	}

	return output.Interface(), nil
}

// StructSliceEncryptTagInterface encrypts fields of a slice of struct (interface{}) based on the tag `tagName:"tagVal"`.
// It returns a new slice with encrypted fields or an error if encryption fails.
func StructSliceEncryptTagInterface(input interface{}, key, tagName, tagVal string) (interface{}, error) {
	if key == "" {
		return input, nil
	}

	// deep copy input
	inputCopy := Copy(input)

	v := reflect.ValueOf(inputCopy)

	if v.Kind() != reflect.Slice {
		return input, fmt.Errorf("input is not a slice")
	}

	for i := 0; i < v.Len(); i++ {
		item := v.Index(i)

		// check if item is a struct
		if item.Kind() == reflect.Struct {
			encryptedItem, err := StructEncryptTag(item.Interface(), key, tagName, tagVal)
			if err != nil {
				return input, err
			}
			v.Index(i).Set(reflect.ValueOf(encryptedItem))
			continue
		}

		// check if item is a pointer struct
		if item.Kind() == reflect.Ptr && item.Elem().Kind() == reflect.Struct {
			encryptedItem, err := StructEncryptTag(item.Interface(), key, tagName, tagVal)
			if err != nil {
				return input, err
			}
			v.Index(i).Set(reflect.ValueOf(encryptedItem))
		}
	}

	return v.Interface(), nil
}

// InterfaceEncryptTagInterface encrypts fields of a struct, pointer to struct, or slice (interface{}) based on the tag `tagName:"tagVal"`.
// It returns a new value with encrypted fields or an error if encryption fails.
func InterfaceEncryptTagInterface(input interface{}, key, tagName, tagVal string) (interface{}, error) {
	if key == "" {
		return input, nil
	}

	v := reflect.ValueOf(input)

	// check if input is a struct
	if v.Kind() == reflect.Struct {
		if result, err := StructEncryptTagInterface(v.Interface(), key, tagName, tagVal); err != nil {
			return input, err
		} else {
			return result, nil
		}
	}

	// check if item is a pointer struct
	if v.Kind() == reflect.Ptr && v.Elem().Kind() == reflect.Struct {
		if result, err := StructEncryptTagInterface(v.Interface(), key, tagName, tagVal); err != nil {
			return input, err
		} else {
			return result, nil
		}
	}

	// check if input is a slice
	if v.Kind() == reflect.Slice {
		if result, err := StructSliceEncryptTagInterface(v.Interface(), key, tagName, tagVal); err != nil {
			return input, err
		} else {
			return result, nil
		}
	}

	return input, nil
}
