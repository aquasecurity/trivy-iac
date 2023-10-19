package armjson

import (
	"fmt"
	"reflect"
)

func (n *node) decodeString(v reflect.Value) error {

	switch v.Kind() {
	case reflect.String:
		v.SetString(n.raw.(string))
	case reflect.Interface:
		v.Set(reflect.ValueOf(n.raw))
	default:
		if n.ref != "properties" {
			return fmt.Errorf("cannot decode string value %v to non-string target: %s", v, v.Kind())
		}
	}
	return nil
}
