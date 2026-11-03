package example

// This is a template implementation showing how to create a custom label store.
// Copy this file and modify it for your specific backend.

import (
	"github.com/rs/zerolog/log"
)

// ExampleHandler is a template label store implementation.
// Replace this with your actual backend implementation.
type ExampleHandler struct {
	// Add your backend connection fields here
	// Example: client *http.Client, apiKey string, baseURL string
}

// Connect establishes a connection with your backend.
// This method is called during application initialization.
func (e *ExampleHandler) Connect(app interface{}) error {
	// TODO: Implement your connection logic
	// Example steps:
	// 1. Read configuration from app.Cfg()
	// 2. Initialize connection to your backend
	// 3. Verify connection is working
	// 4. Log connection status

	log.Info().Msg("ExampleHandler: Connected to backend")
	return nil
}

// GetLabels retrieves labels for the given OAuth token.
// Returns a map of allowed labels and a boolean indicating cluster-wide access.
func (e *ExampleHandler) GetLabels(token interface{}) (map[string]bool, bool) {
	// TODO: Implement your label retrieval logic
	// Example steps:
	// 1. Extract username/email/groups from token
	// 2. Query your backend for allowed labels
	// 3. Check for cluster-wide access (#cluster-wide)
	// 4. Return label map and cluster-wide flag

	// Example structure:
	// username := token.PreferredUsername
	// groups := token.Groups
	//
	// labels := make(map[string]bool)
	// for _, group := range groups {
	//     groupLabels := e.queryBackend(group)
	//     for label := range groupLabels {
	//         if label == "#cluster-wide" {
	//             return nil, true
	//         }
	//         labels[label] = true
	//     }
	// }
	//
	// return labels, false

	log.Warn().Msg("ExampleHandler: Template implementation, returning empty labels")
	return make(map[string]bool), false
}
