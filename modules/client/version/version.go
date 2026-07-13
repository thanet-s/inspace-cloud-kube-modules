// Package version exposes build metadata shared by the InSpace controllers.
package version

// Version is replaced from the release tag by the container build. Development
// builds deliberately report "dev" instead of pretending to be a release.
var Version = "dev"

// UserAgent returns the component user agent sent to the InSpace API.
func UserAgent(component string) string {
	return component + "/" + Version
}
