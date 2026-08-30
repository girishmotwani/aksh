package pipeline

import "fmt"

type InjectStage struct{}

func (s *InjectStage) Name() string { return "inject" }

func (s *InjectStage) Execute(rc *RequestContext) Decision {
	if rc == nil || rc.Request == nil {
		return DenyFault(ReasonInternal, fmt.Errorf("request context missing request"))
	}

	tokenValue := rc.TokenResult.Token.Reveal()
	if tokenValue == "" {
		return Allow()
	}

	// Materialise the secret only at the final post-audit boundary. No later
	// policy or hook stage should receive the request once this header exists.
	rc.Request.Header.Set("Authorization", "Bearer "+tokenValue)
	return Allow()
}
