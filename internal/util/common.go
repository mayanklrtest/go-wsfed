package util

import (
	uuid "github.com/satori/go.uuid"
	"strings"
)

type ClaimAttr struct {
	Format string
	Name   string
}

func ID() string {
	u := uuid.NewV4()
	return "_" + u.String()
}

func GetClaimAttribute(c string) *ClaimAttr {
	clameAttr := &ClaimAttr{
		Format: "",
		Name:   "",
	}
	if strings.Contains(c, "/") {
		index := strings.LastIndex(c, "/")
		if len(c) > index+1 {
			clameAttr.Name = c[index+1:]
			clameAttr.Format = c[:index]
		}
	}
	return clameAttr
}
