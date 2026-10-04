[CmdletBinding(PositionalBinding=$false)]
param([Parameter(Position=0,ValueFromRemainingArguments=$true)][string[]]$ProtocolArgs, [string]$Python = 'python')
$ErrorActionPreference = 'Stop'
$protocolPython = $Python
if (-not (Get-Command $protocolPython -ErrorAction SilentlyContinue)) { throw '请安装 Python 并加入 PATH，或通过 -Python 指定解释器路径。' }
if ($ProtocolArgs.Count -gt 0 -and $ProtocolArgs[0] -eq 'connect-once') {
    $connectArgs = @($ProtocolArgs | Select-Object -Skip 1)
    & $protocolPython -X utf8 (Join-Path $PSScriptRoot 'connect_once.py') @connectArgs
} else {
    & $protocolPython -X utf8 (Join-Path $PSScriptRoot 'cloudpc_protocol.py') @ProtocolArgs
}
exit $LASTEXITCODE
