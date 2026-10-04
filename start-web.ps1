param([int]$Port = 8765, [string]$Python = 'python')
$ErrorActionPreference = 'Stop'
if (-not (Get-Command $Python -ErrorAction SilentlyContinue)) { throw '请安装 Python 并加入 PATH，或通过 -Python 指定解释器路径。' }
& $Python -X utf8 (Join-Path $PSScriptRoot 'web\server.py') --port $Port
exit $LASTEXITCODE
