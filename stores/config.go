package stores

type StoreConfig struct {
	Version int         `yaml:"version"`
	Table   TableConfig `yaml:"table"`
}

type TableConfig struct {
	Name       string                  `yaml:"name"`
	AutoCreate bool                    `yaml:"auto_create"`
	Columns    map[string]ColumnConfig `yaml:"columns"`
}

type ColumnConfig struct {
	Type       string `yaml:"type"`
	PrimaryKey bool   `yaml:"primary_key"`
	Unique     bool   `yaml:"unique"`
	Required   bool   `yaml:"required"`
	Default    string `yaml:"default"`
	Hidden     bool   `yaml:"hidden"`
	JWTClaim   string `yaml:"jwt_claim"`
}

var allowedTypes = map[string]string{
	"text":      "TEXT",
	"int":       "INTEGER",
	"bool":      "BOOLEAN",
	"uuid":      "UUID",
	"jsonb":     "JSONB",
	"timestamp": "TIMESTAMP",
}
