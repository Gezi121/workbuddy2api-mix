// login.go — WorkBuddy CN OAuth 登录（设备授权流程，CN realm only）。
//
// 两个子命令，由 login.sh 顺序驱动：
//
//	login url   → POST /v2/plugin/auth/state?platform=CLI 拿 state+authUrl，
//	              state 落 /tmp/wb2api-login-state.json，stdout 打印授权 URL
//	login poll  → 读 state，GET /v2/plugin/auth/token?state= 一次，
//	              成功再 GET /v2/plugin/login/account?state= 拿 uid/nickname，
//	              stdout 打印完整 token+account JSON
//
// 无 PKCE（workbuddy 设备流由服务端签发 state）。
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// 上游常量：域名与端点由 upstream 包的收口函数按区域给，这里不再写死。
// 区域在运行时选：`login url intl` 或 `WB2API_REGION=intl`（默认国内版）。
const (
	clientUA = "CLI/2.63.2 CodeBuddy/2.63.2"
)

// commonHeaders 通用请求头（Origin/Referer 随区域：国内 codebuddy.cn / 国际 codebuddy.ai）。
func commonHeaders(req *http.Request, origin string) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", origin+"/")
	req.Header.Set("User-Agent", clientUA)
}

// apiEnvelope 与 main.go:429-433 一致
type apiEnvelope struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

// doJSON 与 oauth.go:33-66 一致：{code,msg,data} 信封，code!=0 → error。
// origin 用于没传 headers 时的默认头（随区域）。
func doJSON(client *http.Client, method, fullURL, origin string, headers func(*http.Request), body io.Reader) (json.RawMessage, int, error) {
	req, err := http.NewRequest(method, fullURL, body)
	if err != nil {
		return nil, 0, err
	}
	if headers != nil {
		headers(req)
	} else {
		commonHeaders(req, origin)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, resp.StatusCode, fmt.Errorf("http_error: upstream %d", resp.StatusCode)
	}
	if resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("http_error: upstream redirect %d", resp.StatusCode)
	}
	var env apiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("parse failed: %w", err)
	}
	if env.Code != 0 {
		return nil, resp.StatusCode, fmt.Errorf("code=%d msg=%s", env.Code, env.Msg)
	}
	return env.Data, resp.StatusCode, nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "login: "+format+"\n", args...)
	os.Exit(1)
}

type loginState struct {
	State string `json:"state"`
}

func main() {
	if len(os.Args) < 2 {
		fatal("usage: login <url|poll> [cn|intl]")
	}
	// 区域：位置参数 > 环境变量 WB2API_REGION > 默认国内版。
	// 国际版走 codebuddy.ai 的授权端点（两版 /v2/plugin/auth/* 同构）。
	region := upstream.RegionFromLabel(os.Getenv("WB2API_REGION"))
	if len(os.Args) >= 3 {
		region = upstream.RegionFromLabel(os.Args[2])
	}
	base := upstream.LoginBase(region)
	origin := upstream.OriginBase(region)
	endpointAuthState := base + "/v2/plugin/auth/state?platform=CLI"
	endpointLoginAcct := base + "/v2/plugin/login/account?state="
	endpointAuthToken := base + "/v2/plugin/auth/token?state="
	// state 文件按区域分开，两个区域的登录不互相覆盖。
	// 用系统临时目录（原写死 /tmp 在 Windows 上不可用）。
	stateFile := filepath.Join(os.TempDir(), "wb2api-login-state-"+upstream.RegionLabel(region)+".json")
	// 每个流程独立 cookie jar（oauth.go:22-29：多账号登录互不串会话）
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: 30 * time.Second, Jar: jar}

	switch os.Args[1] {
	case "url":
		// handleStartLogin (oauth.go:68-87)
		data, _, err := doJSON(client, http.MethodPost, endpointAuthState, origin, nil, bytes.NewReader([]byte("{}")))
		if err != nil {
			fatal("auth state failed: %v", err)
		}
		var st struct {
			State   string `json:"state"`
			AuthURL string `json:"authUrl"`
		}
		if err := json.Unmarshal(data, &st); err != nil || st.State == "" || st.AuthURL == "" {
			fatal("auth state: missing state or authUrl")
		}
		raw, _ := json.Marshal(loginState{State: st.State})
		if err := os.WriteFile(stateFile, raw, 0o600); err != nil {
			fatal("write state: %v", err)
		}
		fmt.Println(st.AuthURL)

	case "poll":
		raw, err := os.ReadFile(stateFile)
		if err != nil {
			fatal("read state: %v (先跑 login url)", err)
		}
		var ls loginState
		if err := json.Unmarshal(raw, &ls); err != nil {
			fatal("parse state: %v", err)
		}
		// handlePollLogin (oauth.go:108-162)：auth/token 是权威登录状态端点，
		// pending 时业务 code 非 0（"login ing"），完成时 code=0 + token bundle
		tokRaw, status, errTok := doJSON(client, http.MethodGet, endpointAuthToken+ls.State, origin, nil, nil)
		if errTok != nil {
			if status == 0 || status >= 500 {
				fatal("token endpoint error: %v", errTok)
			}
			fatal("登录未完成（waiting for login）。请确认已在浏览器完成登录再按 y")
		}
		var tok struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
			ExpiresIn    int64  `json:"expiresIn"`
			Domain       string `json:"domain"`
		}
		if err := json.Unmarshal(tokRaw, &tok); err != nil || tok.AccessToken == "" {
			fatal("登录未完成（waiting for login）。请确认已在浏览器完成登录再按 y")
		}
		// login/account 拿 uid/nickname（带 Bearer）
		var acct struct {
			UID          string `json:"uid"`
			EnterpriseID string `json:"enterpriseId"`
			Nickname     string `json:"nickname"`
		}
		acctHeaders := func(r *http.Request) {
			commonHeaders(r, origin)
			r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		}
		if acctRaw, _, errAcct := doJSON(client, http.MethodGet, endpointLoginAcct+ls.State, origin, acctHeaders, nil); errAcct == nil {
			_ = json.Unmarshal(acctRaw, &acct)
		}
		out := map[string]any{
			"access_token":  tok.AccessToken,
			"refresh_token": tok.RefreshToken,
			"expires_in":    tok.ExpiresIn,
			"domain":        tok.Domain,
			"uid":           acct.UID,
			"enterprise_id": acct.EnterpriseID,
			"nickname":      acct.Nickname,
		}
		oraw, _ := json.Marshal(out)
		fmt.Println(string(oraw))
		os.Remove(stateFile)

	default:
		fatal("unknown subcommand %q (want url|poll)", os.Args[1])
	}
}
