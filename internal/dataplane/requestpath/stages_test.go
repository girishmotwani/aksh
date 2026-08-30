package requestpath

import "github.com/girishmotwani/aksh/internal/pipeline"

// stageSlice builds the standard request-phase stage list used by the tests in
// this package. Production assembles its own list in internal/runtime/assembly.go;
// this helper exists only so tests can vary the match and acquire stages while
// keeping the surrounding stages fixed.
func stageSlice(matchStage, acquireStage pipeline.Stage) []pipeline.Stage {
	return []pipeline.Stage{
		&pipeline.SanitiseStage{},
		&pipeline.IdentityStage{},
		matchStage,
		acquireStage,
		&pipeline.InjectStage{},
	}
}
