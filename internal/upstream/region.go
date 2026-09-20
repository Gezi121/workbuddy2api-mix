// region.go 上游区域：国内版（codebuddy.cn / workbuddy.cn / copilot.tencent.com）
// 与国际版（codebuddy.ai / workbuddy.ai）。
//
// 两版协议**同构** —— 同一套 `/v2/plugin/auth/*`、`/v2/chat/completions`、
// `/v2/billing/meter/*` 路径，差别只在域名与身份头（Origin/Referer 与 X-Domain）。
// 所以区域路由只需要几个"收口函数"：chatBase / billingBase / webBase /
// originRefererFor —— 其余业务代码一行都不用动。
//
// 判定依据是账号凭证里的 `domain`：它由登录响应写入（面板「添加账号」或 CLI
// 授权那一步），国际版账号登录后自然是 `*.ai`，不需要用户额外声明。
package upstream

import (
	"strings"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// Region 上游区域。
type Region int

const (
	// RegionCN 国内版（codebuddy.cn / workbuddy.cn）。
	RegionCN Region = iota
	// RegionINTL 国际版（codebuddy.ai / workbuddy.ai）。
	RegionINTL
)

// 国内版默认域（Client 的 *CN 字段仍可覆盖，便于测试与自建网关）。
const (
	chatBaseCN    = "https://copilot.tencent.com"
	billingBaseCN = "https://www.codebuddy.cn"
	webBaseCN     = "https://www.workbuddy.cn"
)

// 国际版域：统一走 workbuddy.ai。
//
// 曾经用过 www.codebuddy.ai（腾讯另一条海外入口），现在**只做 workbuddy 系**：
//   - 实测 workbuddy.ai 的 `/v2/plugin/auth/state?platform=CLI` 返回 200（登录可用）；
//   - 计费/签到族（/v2/billing/meter/*）在该域上齐全（假路径 404、真路径 401）；
//   - SadPull/cpa-plugin 的记录：copilot.tencent.com 会拒 Global JWT，国际版必须走 workbuddy.ai。
//
// 所以 chat / billing / web / 登录 Origin 全部收在这一个域上。
const intlBase = "https://www.workbuddy.ai"

const (
	chatBaseINTL    = intlBase
	billingBaseINTL = intlBase
	webBaseINTL     = intlBase
)

// originRefererCN / originRefererINTL 出站 Origin 与 Referer 的基址。
const (
	originRefererCN   = "https://www.codebuddy.cn"
	originRefererINTL = intlBase
)

// RegionOf 按账号凭证的 domain 判断区域（domain 为空的老凭证按国内版）。
func RegionOf(a *auth.Auth) Region {
	if a == nil {
		return RegionCN
	}
	return RegionOfDomain(a.Domain)
}

// RegionOfDomain 按域名字符串判断区域。
//
// 登录流程在拿到 domain 之前也要用（发起授权时用户已经选定区域），
// 所以判定与账号解耦，单独留一个字符串版本。
func RegionOfDomain(domain string) Region {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d != "" && strings.Contains(d, ".ai") {
		return RegionINTL
	}
	return RegionCN
}

// RegionLabel 给日志/接口用的小写标签（"cn" / "intl"）。
func RegionLabel(r Region) string {
	if r == RegionINTL {
		return "intl"
	}
	return "cn"
}

// RegionFromLabel 解析区域标签（"intl"/"international"/"global" → 国际版，其余国内版）。
func RegionFromLabel(s string) Region {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "intl", "international", "global", "ai", "overseas":
		return RegionINTL
	default:
		return RegionCN
	}
}

// LoginBase 发起设备授权（OAuth）用的基址：
// 国内 copilot.tencent.com，国际 codebuddy.ai（两版 /v2/plugin/auth/* 路径同构）。
//
// 供面板与 cmd/login 共用 —— 登录端点只在这一处写域名，免得两边各抄一份。
func LoginBase(region Region) string {
	if region == RegionINTL {
		return chatBaseINTL
	}
	return chatBaseCN
}

// OriginBase 该区域出站 Origin/Referer 的基址（登录流程用；业务请求见 originRefererFor）。
func OriginBase(region Region) string {
	if region == RegionINTL {
		return originRefererINTL
	}
	return originRefererCN
}

// BillingBase 按区域给 billing 域基址（credit 这类独立小工具用；
// 主链路走 Client.billingBase(a)，按账号 domain 自动分流）。
func BillingBase(region Region) string {
	if region == RegionINTL {
		return billingBaseINTL
	}
	return billingBaseCN
}
