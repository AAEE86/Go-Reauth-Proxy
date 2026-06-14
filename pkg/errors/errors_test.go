package errors

import (
	"go-reauth-proxy/pkg/i18n"
	"testing"
)

func TestGetMessageForLocale(t *testing.T) {
	if got := GetMessageForLocale(i18n.LocaleZhCN, CodeSuccess); got != "成功" {
		t.Fatalf("zh-CN success = %q", got)
	}
	if got := GetMessageForLocale(i18n.LocaleEn, CodeSuccess); got != "Success" {
		t.Fatalf("en success = %q", got)
	}
	if got := GetMessageForLocale(i18n.LocaleZhHant, CodeInvalidJSON); got != "JSON 格式無效" {
		t.Fatalf("zh-Hant invalid json = %q", got)
	}
	if got := GetMessageForLocale(i18n.LocaleEn, 99999); got != "Unknown Error" {
		t.Fatalf("unknown error = %q", got)
	}
}

func TestGetMessageUsesDefaultLocale(t *testing.T) {
	i18n.SetDefaultLocale(i18n.LocaleEn)
	t.Cleanup(func() {
		i18n.SetDefaultLocale(i18n.DefaultLocale)
	})

	if got := GetMessage(CodeBadRequest); got != "Bad Request" {
		t.Fatalf("default locale message = %q", got)
	}
}
