// region_test.go 区域路由：国内版（codebuddy.cn / copilot.tencent.com）与
// 国际版（codebuddy.ai / workbuddy.ai）按账号 domain 分流。
//
// 这一层是新加的：上游原本只有国内域，所有出站端点写死 codebuddy.cn。改造后
// 域的选择收口在 chatBase / billingBase / webBase / originRefererFor 四个函数，
// 判定依据是凭证里的 domain —— 这些测试就是那条收口的警戒线。
package upstream

import (
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

func TestRegionOfUsesAccountDomain(t *testing.T) {
	cases := []struct {
		domain string
		want   Region
	}{
		{"www.codebuddy.cn", RegionCN},
		{"www.workbuddy.cn", RegionCN},
		{"copilot.tencent.com", RegionCN},
		{"www.codebuddy.ai", RegionINTL},
		{"www.workbuddy.ai", RegionINTL},
		{"codebuddy.ai", RegionINTL},
		{"WWW.CODEBUDDY.AI", RegionINTL}, // 大小写不敏感
		{" www.workbuddy.ai ", RegionINTL},
		{"", RegionCN}, // 老凭证没有 domain：保持国内版行为
	}
	for _, c := range cases {
		if got := RegionOf(&auth.Auth{Domain: c.domain}); got != c.want {
			t.Errorf("RegionOf(domain=%q) = %v, want %v", c.domain, got, c.want)
		}
	}
	// nil 账号不能 panic（调用方可能传空）
	if got := RegionOf(nil); got != RegionCN {
		t.Errorf("RegionOf(nil) = %v, want CN", got)
	}
}

func TestBaseURLsFollowTheRegion(t *testing.T) {
	c := New()
	cn := &auth.Auth{Domain: "www.codebuddy.cn"}
	intl := &auth.Auth{Domain: "www.workbuddy.ai"}

	if got := c.chatBase(cn); got != chatBaseCN {
		t.Errorf("chatBase(cn) = %q, want %q", got, chatBaseCN)
	}
	if got := c.chatBase(intl); got != chatBaseINTL {
		t.Errorf("chatBase(intl) = %q, want %q（国际版对话走 codebuddy.ai）", got, chatBaseINTL)
	}
	if got := c.billingBase(cn); got != billingBaseCN {
		t.Errorf("billingBase(cn) = %q, want %q", got, billingBaseCN)
	}
	if got := c.billingBase(intl); got != billingBaseINTL {
		t.Errorf("billingBase(intl) = %q, want %q", got, billingBaseINTL)
	}
	if got := c.webBase(cn); got != webBaseCN {
		t.Errorf("webBase(cn) = %q, want %q", got, webBaseCN)
	}
	if got := c.webBase(intl); got != webBaseINTL {
		t.Errorf("webBase(intl) = %q, want %q（成长中心走 workbuddy.ai）", got, webBaseINTL)
	}
	// 国内版仍认注入的覆盖值（测试/自建网关靠它打本地服务器）
	c.WebBaseCN = "https://example.test"
	if got := c.webBase(cn); got != "https://example.test" {
		t.Errorf("webBase(cn) = %q, want 注入的覆盖值", got)
	}
	// 但国际版不接受国内覆盖：不能把国际账号打到国内域上
	if got := c.webBase(intl); got != webBaseINTL {
		t.Errorf("webBase(intl) = %q, want %q（覆盖值只作用于国内版）", got, webBaseINTL)
	}
}

func TestOriginRefererFollowsTheRegion(t *testing.T) {
	if got := originRefererFor(&auth.Auth{Domain: "www.codebuddy.cn"}); got != originRefererCN {
		t.Errorf("origin(cn) = %q, want %q", got, originRefererCN)
	}
	if got := originRefererFor(&auth.Auth{Domain: "www.codebuddy.ai"}); got != originRefererINTL {
		t.Errorf("origin(intl) = %q, want %q", got, originRefererINTL)
	}
}

// 模型目录路径两版不同 —— 国际版打 /console/... 会被网关 500（实测），必须走 /v2/。
func TestModelsPathFollowsTheRegion(t *testing.T) {
	cn := &auth.Auth{Domain: "www.codebuddy.cn"}
	intl := &auth.Auth{Domain: "www.workbuddy.ai"}
	if got := modelsPathFor(cn); got != "/console/enterprises/personal/models" {
		t.Errorf("modelsPath(cn) = %q, want /console/enterprises/personal/models", got)
	}
	if got := modelsPathFor(intl); got != "/v2/enterprises/personal/models" {
		t.Errorf("modelsPath(intl) = %q, want /v2/enterprises/personal/models（打 /console 会 500）", got)
	}
}

// 补充模型只对国际版生效，且必须包含实测可用的 deepseek-v4.1-flash。
func TestSupplementalModelsOnlyForIntl(t *testing.T) {
	if got := supplementalModels(&auth.Auth{Domain: "www.codebuddy.cn"}); got != nil {
		t.Errorf("国内版不该有补充模型，got %v", got)
	}
	got := supplementalModels(&auth.Auth{Domain: "www.workbuddy.ai"})
	if len(got) != 1 || got[0].ID != "deepseek-v4.1-flash" {
		t.Fatalf("国际版补充模型应含 deepseek-v4.1-flash，got %+v", got)
	}
	if got[0].ContextWindow == 0 || got[0].MaxTokens == 0 {
		t.Errorf("补充模型缺元数据：%+v", got[0])
	}
}

func TestRegionLabelsRoundTrip(t *testing.T) {
	for _, s := range []string{"intl", "international", "global", "INTL", "ai"} {
		if got := RegionFromLabel(s); got != RegionINTL {
			t.Errorf("RegionFromLabel(%q) = %v, want INTL", s, got)
		}
	}
	for _, s := range []string{"", "cn", "china", "随便什么"} {
		if got := RegionFromLabel(s); got != RegionCN {
			t.Errorf("RegionFromLabel(%q) = %v, want CN（默认国内版）", s, got)
		}
	}
	if RegionLabel(RegionINTL) != "intl" || RegionLabel(RegionCN) != "cn" {
		t.Errorf("RegionLabel 标签不对: %q/%q", RegionLabel(RegionCN), RegionLabel(RegionINTL))
	}
}
