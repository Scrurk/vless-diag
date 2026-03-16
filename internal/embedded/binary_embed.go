//go:build embed_singbox

package embedded

import _ "embed"

//go:embed sing-box.exe
var SingBoxBinary []byte
