// ua_test.go 出站 UA 的区域适配 + 登录用 JWT 解析。
//
// 移植自专职国际版项目的做法：国内版是 CodeBuddy 品牌、国际版是 WorkBuddy 品牌，
// 拿错品牌打错域是"本可避免的不匹配"，登录时尤其容易被风控。
package upstream

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// 造一个与上游同形的 JWT（只关心 payload，签名随意）。
func fakeJWT(payload string) string {
	seg := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return "eyJhbGciOiJSUzI1NiJ9." + seg + ".sig"
}

func TestUserAgentFollowsRegion(t *testing.T) {
	cn := userAgentFor(&auth.Auth{Domain: "www.codebuddy.cn"})
	if !strings.Contains(cn, "CodeBuddy") {
		t.Errorf("国内版 UA 该是 CodeBuddy 品牌，got %q", cn)
	}
	if strings.Contains(cn, "WorkBuddy AI") {
		t.Errorf("国内版 UA 不该混进国际版品牌：%q", cn)
	}

	intl := userAgentFor(&auth.Auth{Domain: "www.workbuddy.ai"})
	if !strings.HasPrefix(intl, "WorkBuddy/") {
		t.Errorf("国际版 UA 该以 WorkBuddy/ 开头，got %q", intl)
	}
	for _, want := range []string{"WorkBuddy AI/", "CLI/"} {
		if !strings.Contains(intl, want) {
			t.Errorf("国际版 UA 缺 %q：%q", want, intl)
		}
	}
	// 三个片段共用同一个版本号
	parts := strings.Split(intl, " ")
	vers := map[string]bool{}
	for _, p := range parts {
		if _, v, ok := strings.Cut(p, "/"); ok {
			vers[v] = true
		}
	}
	if len(vers) != 1 {
		t.Errorf("UA 里版本号该是一致的：%q", intl)
	}
	// 品牌里不能出现国内版的 CodeBuddy
	if strings.Contains(intl, "CodeBuddy") {
		t.Errorf("国际版 UA 不该含 CodeBuddy：%q", intl)
	}
}

func TestJWTClaimsHelpLoginSkipARequest(t *testing.T) {
	intlTok := fakeJWT(`{"iss":"https://www.workbuddy.ai/auth/realms/copilot",` +
		`"sub":"8fabb5e7-880f-4af0-973f-5adda2c4f923","preferred_username":"a@b.com"}`)

	if !IsIntlToken(intlTok) {
		t.Error("issuer 含 workbuddy.ai 应判为国际版")
	}
	if got := JWTUID(intlTok); got != "8fabb5e7-880f-4af0-973f-5adda2c4f923" {
		t.Errorf("JWTUID = %q（该从 sub 取，省掉一次 /login/account 请求）", got)
	}
	if got := JWTNickname(intlTok); got != "a@b.com" {
		t.Errorf("JWTNickname = %q（该从 preferred_username 取）", got)
	}

	cnTok := fakeJWT(`{"iss":"https://www.codebuddy.cn/auth/realms/copilot","sub":"u1"}`)
	if IsIntlToken(cnTok) {
		t.Error("国内版 issuer 不该判为国际版")
	}
	// 国际版有两个 realm：codebuddy.ai 与 workbuddy.ai，都算国际版
	aiTok := fakeJWT(`{"iss":"https://www.codebuddy.ai/auth/realms/copilot","sub":"u2"}`)
	if !IsIntlToken(aiTok) {
		t.Error("codebuddy.ai 是国际版 realm 之一，不该被判成国内版")
	}
	if got := JWTUID(aiTok); got != "u2" {
		t.Errorf("JWTUID(codebuddy.ai token) = %q", got)
	}

	// 解析不出来时不能 panic，也不能瞎判
	if IsIntlToken("not-a-jwt") || JWTUID("not-a-jwt") != "" || JWTNickname("") != "" {
		t.Error("非 JWT 输入应安全返回空值")
	}
}
