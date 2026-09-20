// ua.go 出站 User-Agent 的区域适配，以及登录时用的 JWT 解析。
//
// 国内版与国际版是**两个发行版**：国内叫 CodeBuddy，国际叫 WorkBuddy。
// 各自的官方客户端发的 UA 品牌不同：
//
//	国内  CLI/2.63.2 CodeBuddy/2.63.2
//	国际  WorkBuddy/5.5.2 WorkBuddy AI/5.5.2 CLI/5.5.2
//
// 拿国内味的 UA 去打国际版凭据，是"本可避免的不匹配"（专职国际版项目的原话），
// 登录添加账号时尤其容易触发风控 —— 所以按账号区域分开发。
package upstream

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// 国际版官方客户端的品牌标识。
const (
	intlUAPlatform = "WorkBuddy"
	intlUAProduct  = "WorkBuddy AI"
	// 读不到本机版本时的回落值（官方升级后本机会读到新值，这里只是兜底）。
	intlUAFallbackVersion = "5.5.2"
)

// intlClientVersion 尽力读本机官方客户端版本号。
//
// 版本号是 UA 的一部分，写死会在官方升级后变成"旧版本客户端"。官方把版本写在这两个
// 文件里（Windows 与 *nix 都在家目录下），读得到就用真实值，读不到回落常量。
func intlClientVersion() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return intlUAFallbackVersion
	}
	for _, c := range []struct{ rel, key string }{
		{filepath.Join(".workbuddy-ai", "last-launch.json"), "version"},
		{filepath.Join(".workbuddy-ai", "cache", "acc-product-config-v3.json"), "genieVersion"},
	} {
		raw, err := os.ReadFile(filepath.Join(home, c.rel))
		if err != nil {
			continue
		}
		var doc map[string]any
		if json.Unmarshal(raw, &doc) != nil {
			continue
		}
		if v, _ := doc[c.key].(string); strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return intlUAFallbackVersion
}

// IntlUserAgent 国际版出站 UA：`WorkBuddy/<ver> WorkBuddy AI/<ver> CLI/<ver>`。
func IntlUserAgent() string {
	v := intlClientVersion()
	return intlUAPlatform + "/" + v + " " + intlUAProduct + "/" + v + " CLI/" + v
}

// userAgentFor 按账号区域给出站 UA。
func userAgentFor(a *auth.Auth) string {
	if RegionOf(a) == RegionINTL {
		return IntlUserAgent()
	}
	return clientUA
}

// jwtClaims 解出 JWT 的 payload（**不校验签名** —— 只读 issuer / uid / exp 这些公开声明）。
func jwtClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}
	seg := parts[1]
	if pad := len(seg) % 4; pad != 0 {
		seg += strings.Repeat("=", 4-pad)
	}
	raw, err := base64.URLEncoding.DecodeString(seg)
	if err != nil {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

// JWTIssuer 取 token 的 issuer（小写）；解析失败返回空串。
func JWTIssuer(token string) string {
	s, _ := jwtClaims(token)["iss"].(string)
	return strings.ToLower(s)
}

// JWTUID 从 token 里取账号 uid（官方放在 uid / sub / userId 之一）。
//
// 登录时用它拿 uid，可以**少打一次** `/v2/plugin/login/account` —— 添加账号的过程
// 越少请求，越不容易被风控盯上（专职国际版项目就是这么做的，nickname 才走那个接口）。
func JWTUID(token string) string {
	c := jwtClaims(token)
	for _, k := range []string{"uid", "sub", "userId"} {
		if s, _ := c[k].(string); strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// IsIntlToken 判断凭据是否属于国际版 realm。
//
// 注意国际版**有两个 realm**（实测自家账号）：
//
//	www.workbuddy.ai/auth/realms/copilot   （WorkBuddy 系）
//	www.codebuddy.ai/auth/realms/copilot   （CodeBuddy 系）
//
// 二者都是国际版、都含 ".ai"；国内版是 .cn。所以判据是 ".ai"，**不能**写成
// 只认 workbuddy.ai —— 那样会把 codebuddy.ai 的账号误判成国内版拒之门外。
func IsIntlToken(token string) bool {
	return strings.Contains(JWTIssuer(token), ".ai")
}

// JWTNickname 从 token 里取展示名。
//
// 国际版的显示名就是 `preferred_username`（登录邮箱），与 /login/account 返回的
// nickname 一致 —— 所以添加账号时可以不再打那个接口，少一次请求。
func JWTNickname(token string) string {
	c := jwtClaims(token)
	for _, k := range []string{"preferred_username", "name", "email"} {
		if s, _ := c[k].(string); strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}
