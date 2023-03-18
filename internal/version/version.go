package version

var (
	Version = "xxx"

	BuildMetadata = "unreleased"
)

func GetVersion() string {
	if BuildMetadata == "" {
		return Version
	}
	return Version + "+" + BuildMetadata
}
