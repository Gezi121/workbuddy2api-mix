// login.go 面板内嵌的 WorkBuddy CN OAuth 设备授权流程（cmd/login 的进程内移植）。
//
//	POST /panel/api/login/start → 拿 state+authUrl，state 存进程内（不再落 /tmp，
//	  原方案在 Windows 上不可用），返回授权 URL；
//	GET  /panel/api/login/poll   → 面板前端每 3s 轮询本接口；未完成返回 done=false，
//	  完成后取 uid/nickname、凭证落盘 auths/workbuddy-<uid>.json、热加载进池
//	  （pool.Add + Revive），并顺带签到 + 余额刷新 —— 免重启加载新账号。
//
// 无 PKCE（workbuddy 设备流由服务端签发 state），请求头与上游端点与 cmd/login 保持一致。
package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

const (
	clientUA = "CLI/2.63.2 CodeBuddy/2.63.2"
)

// loginSession 一次进行中的授权会话：发起时刻 + 用户选定的区域。
// 区域必须记下来 —— poll 阶段还没拿到凭证，无法从 domain 反推该打哪个端点。
type loginSession struct {
	created time.Time
	region  upstream.Region
}

// loginEndpoints 一个区域的一套登录端点与身份头。
//
// 两版路径同构，差异在**域、Origin 和 UA 品牌**：国内是 CodeBuddy 品牌，
// 国际是 WorkBuddy 品牌（拿国内味的 UA 去登录国际版账号容易被风控）。
type loginEndpoints struct {
	authState string
	loginAcct string
	authToken string
	origin    string
	ua        string
}

// loginEndpointsFor 按区域给端点：国内 copilot.tencent.com / codebuddy.cn，
// 国际 codebuddy.ai。区域由面板「添加账号」时选（默认国内版）。
func loginEndpointsFor(region upstream.Region) loginEndpoints {
	base := upstream.LoginBase(region)
	ua := clientUA
	if region == upstream.RegionINTL {
		// 国际版官方客户端是 WorkBuddy 品牌（版本从本机客户端读，见 upstream/ua.go）
		ua = upstream.IntlUserAgent()
	}
	return loginEndpoints{
		authState: base + "/v2/plugin/auth/state?platform=CLI",
		loginAcct: base + "/v2/plugin/login/account?state=",
		authToken: base + "/v2/plugin/auth/token?state=",
		origin:    upstream.OriginBase(region),
		ua:        ua,
	}
}

// loginHTTP 设备授权专用 client：短超时、无 cookie（每请求携带 state，无会话态）。
var loginHTTP = &http.Client{Timeout: 30 * time.Second}

func commonHeaders(req *http.Request, origin, ua string) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", origin+"/")
	req.Header.Set("User-Agent", ua)
}

// validUID 校验上游返回的 uid 是否可安全用于拼文件名。
// 只放行字母、数字、下划线、连字符（腾讯侧 uid 实测为 UUID 形态），
// 长度上限 64 兜底异常超长串；拒绝 . / \ 等路径字符与空串。
func validUID(uid string) bool {
	if uid == "" || len(uid) > 64 {
		return false
	}
	for _, c := range uid {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// apiEnvelope 与 upstream 同形：{code,msg,data}，code!=0 视为业务错误。
type apiEnvelope struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

// doJSON 发一次 JSON 请求并解信封。origin 按区域给（国内 codebuddy.cn / 国际 codebuddy.ai）。
func doJSON(method, fullURL, origin, ua, bearer string, body io.Reader) (json.RawMessage, int, error) {
	req, err := http.NewRequest(method, fullURL, body)
	if err != nil {
		return nil, 0, err
	}
	commonHeaders(req, origin, ua)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := loginHTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("http_error: upstream %d", resp.StatusCode)
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

// loginStart 发起设备授权：POST auth/state 拿授权 URL。
//
// `?region=cn|intl` 选区域（缺省国内版）：国际版走 codebuddy.ai 的授权端点，
// 拿回来的凭证 domain 会是 *.ai —— 后续业务请求据此自动路由到国际版域。
func (p *Panel) loginStart(w http.ResponseWriter, r *http.Request) {
	region := upstream.RegionFromLabel(r.URL.Query().Get("region"))
	ep := loginEndpointsFor(region)
	data, status, err := doJSON(http.MethodPost, ep.authState, ep.origin, ep.ua, "", bytes.NewReader([]byte("{}")))
	if err != nil {
		writeErr(w, http.StatusBadGateway, fmt.Sprintf("auth state (upstream %d): %v", status, err))
		return
	}
	var st struct {
		State   string `json:"state"`
		AuthURL string `json:"authUrl"`
	}
	if err := json.Unmarshal(data, &st); err != nil || st.State == "" || st.AuthURL == "" {
		writeErr(w, http.StatusBadGateway, "auth state: missing state or authUrl")
		return
	}
	p.loginMu.Lock()
	// 顺手回收过期会话，防"开弹窗走开"的 state 滞留。
	for s, sess := range p.logins {
		if time.Since(sess.created) > loginTTL {
			delete(p.logins, s)
		}
	}
	p.logins[st.State] = loginSession{created: time.Now(), region: region}
	p.loginMu.Unlock()
	log.Printf("panel: 发起 OAuth 添加账号（区域=%s state=%s...）",
		upstream.RegionLabel(region), st.State[:min(8, len(st.State))])
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "url": st.AuthURL, "state": st.State,
		"region": upstream.RegionLabel(region),
	})
}

// loginPoll 轮询登录态。未完成 → {done:false}；完成 → 建凭证、落盘、热加载、签到。
func (p *Panel) loginPoll(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		writeErr(w, http.StatusBadRequest, "missing state")
		return
	}
	p.loginMu.Lock()
	sess, known := p.logins[state]
	p.loginMu.Unlock()
	if !known {
		writeErr(w, http.StatusNotFound, "unknown or expired state（请重新发起添加账号）")
		return
	}
	// 用**发起时选定的区域**取端点：不能靠此刻的域名推断，此时还没拿到凭证。
	ep := loginEndpointsFor(sess.region)

	// auth/token 是权威登录状态端点：pending 时业务 code 非 0（"login ing"）。
	tokRaw, _, err := doJSON(http.MethodGet, ep.authToken+state, ep.origin, ep.ua, "", nil)
	if err != nil {
		// pending / 未完成：面板前端继续轮询。
		writeJSON(w, http.StatusOK, map[string]any{"done": false, "message": err.Error()})
		return
	}
	var tok struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    int64  `json:"expiresIn"`
		Domain       string `json:"domain"`
	}
	if err := json.Unmarshal(tokRaw, &tok); err != nil || tok.AccessToken == "" {
		writeJSON(w, http.StatusOK, map[string]any{"done": false, "message": "waiting for login"})
		return
	}

	// 域校验：在哪个入口登录，凭证就得属于哪个 realm。
	//
	// 用户在国际版入口里登了国内账号（或反过来）时，凭证存下来会一直打不通上游，
	// 不如当场把话说清楚。判据是 token 的 JWT issuer（签名过的，比 domain 字段可靠）。
	isIntlToken := upstream.IsIntlToken(tok.AccessToken)
	if sess.region == upstream.RegionINTL && !isIntlToken {
		writeErr(w, http.StatusBadGateway,
			"这个账号属于国内版（token 的 issuer 不含 workbuddy.ai）：请改用「国内版」入口添加它")
		return
	}
	if sess.region == upstream.RegionCN && isIntlToken {
		writeErr(w, http.StatusBadGateway,
			"这个账号属于国际版：请改用「国际版」入口添加它")
		return
	}

	// uid / 显示名：国际版直接从 token 的 JWT 里取（sub 就是 uid，preferred_username
	// 就是登录邮箱），**不再打 /v2/plugin/login/account** —— 添加账号的过程每少一次
	// 请求，被风控盯上的概率就小一分。国内版仍走接口（那边可能要 enterpriseId）。
	uid := ""
	nickname := ""
	enterpriseID := ""
	if sess.region == upstream.RegionINTL {
		uid = upstream.JWTUID(tok.AccessToken)
		nickname = upstream.JWTNickname(tok.AccessToken)
	}
	if uid == "" {
		var acct struct {
			UID          string `json:"uid"`
			EnterpriseID string `json:"enterpriseId"`
			Nickname     string `json:"nickname"`
		}
		if acctRaw, _, err := doJSON(http.MethodGet, ep.loginAcct+state, ep.origin, ep.ua, tok.AccessToken, nil); err == nil {
			_ = json.Unmarshal(acctRaw, &acct)
		}
		uid, nickname, enterpriseID = acct.UID, acct.Nickname, acct.EnterpriseID
	}
	if uid == "" {
		writeErr(w, http.StatusBadGateway, "login done but no uid（token 已发但账号信息获取失败，请重试）")
		return
	}
	// UID 来自上游响应，未经校验就用于拼文件名会被路径穿越利用
	// （filepath.Join("./auths", "workbuddy-../../evil.json") → auths/evil.json）。
	// UID 是腾讯侧账号标识，实测为 UUID（十六进制与连字符），故只放行 [A-Za-z0-9_-]。
	if !validUID(uid) {
		writeErr(w, http.StatusBadGateway, "上游返回的 uid 含非法字符，拒绝落盘（防路径穿越）")
		return
	}

	// 凭证落盘（嵌套形，与 auths/ 目录既有格式一致）→ 热加载进池。
	if err := os.MkdirAll(p.cfg.AuthDir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "mkdir auth dir: "+err.Error())
		return
	}
	a := &auth.Auth{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Unix(),
		Domain:       tok.Domain,
		UID:          uid,
		EnterpriseID: enterpriseID,
		Nickname:     nickname,
		FilePath:     filepath.Join(p.cfg.AuthDir, fmt.Sprintf("workbuddy-%s.json", uid)),
	}
	if err := a.SaveAtomic(); err != nil {
		writeErr(w, http.StatusInternalServerError, "save auth: "+err.Error())
		return
	}
	p.cfg.Pool.Add(a)
	p.cfg.Pool.Revive(uid) // 全新登录 = 人工恢复口径：清掉旧号遗留的禁用/冷却/熔断

	// 顺带签到 + 余额刷新（幂等；失败不影响登录结果，只体现在返回字段里）。
	checkinMsg := ""
	if err := p.cfg.Upstream.DailyCheckin(a); err != nil {
		checkinMsg = err.Error()
	}
	remain := int64(-1)
	if rm, err := p.cfg.Upstream.UserResource(a); err == nil {
		remain = rm
		p.cfg.Pool.ReenableIfCredits(uid, rm)
	}

	p.loginMu.Lock()
	delete(p.logins, state)
	p.loginMu.Unlock()
	log.Printf("panel: 新账号已热加载 uid=%s nickname=%q 区域=%s（免重启生效）",
		uid, nickname, upstream.RegionLabel(sess.region))
	writeJSON(w, http.StatusOK, map[string]any{
		"done":            true,
		"uid":             uid,
		"nickname":        nickname,
		"credits":         remain,
		"checkin_message": checkinMsg,
	})
}
