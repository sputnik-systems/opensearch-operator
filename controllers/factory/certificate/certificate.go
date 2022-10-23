package certificate

import (
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Object interface {
	client.Object
}

type certificate struct {
	s map[string][]Object
	sync.Mutex
}

var c *certificate

func init() {
	s := make(map[string][]Object)
	c = &certificate{s: s}
}

func Add(key string, value Object) {
	c.Lock()
	defer c.Unlock()

	if c.s[key] == nil {
		c.s[key] = make([]Object, 0)
	}

	for _, v := range c.s[key] {
		if v.GetObjectKind().GroupVersionKind().Kind == value.GetObjectKind().GroupVersionKind().Kind && v.GetName() == value.GetName() {
			return
		}
	}

	c.s[key] = append(c.s[key], value)
}

func Remove(value Object) {
	c.Lock()
	defer c.Unlock()

	for k, cs := range c.s {
		var x []int
		for i, v := range cs {
			if v.GetObjectKind().GroupVersionKind().Kind == value.GetObjectKind().GroupVersionKind().Kind && v.GetName() == value.GetName() {
				x = []int{i}

				break
			}
		}

		if x != nil {
			if len(c.s[k]) == 1 {
				delete(c.s, k)
			} else if len(c.s[k]) > 0 {
				c.s[k][x[0]], c.s[k][len(c.s[k])-1] = c.s[k][len(c.s[k])-1], c.s[k][x[0]]
				c.s[k] = c.s[k][:len(c.s[k])-2]
			}
		}
	}
}

func Get(key string) []Object {
	return c.s[key]
}
