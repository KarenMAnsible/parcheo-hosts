param(
    [string[]]$Paths = @("C:\"),
    [string]$OutputFile
)

if (-not $OutputFile) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputFile = "C:\Temp\Vulnerabilidades_Apache_$timestamp.txt"
}

# Crear carpeta destino si no existe
$dir = Split-Path $OutputFile -Parent
if (-not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

function Test-Log4jFile {
    param([System.IO.FileInfo]$File)

    $name   = $File.Name
    $version = $null
    $status  = "Desconocido"
    $detalle = "No se pudo determinar la versión desde el nombre de archivo."

    # Ejemplos: log4j-core-2.13.3.jar, log4j-api-2.14.1.jar
    $regex = [regex]'log4j(-core)?-(?<ver>\d+\.\d+(\.\d+)*)\.jar'
    $m = $regex.Match($name)
    if ($m.Success) {
        $versionString = $m.Groups['ver'].Value
        try {
            $v = [version]$versionString
            $version = $versionString

            $isCore = $name -like "log4j-core*"

            if ($isCore -and $v -ge [version]"2.0.0" -and $v -lt [version]"2.15.0") {
                $status  = "VULNERABLE (CVE-2021-44228)"
                $detalle = "log4j-core $version afectado: actualizar a 2.17.x"
            }
            elseif ($isCore -and $v -ge [version]"2.15.0" -and $v -lt [version]"2.17.0") {
                $status  = "Revisar (parcialmente mitigado)"
                $detalle = "log4j-core $version tiene mitigación parcial, actualizar a 2.17.x"
            }
            else {
                $status  = "OK"
                $detalle = "log4j-core $version fuera del rango vulnerable."
            }
        } catch {
            $status  = "Desconocido"
            $detalle = "Error procesando versión."
        }
    }

    [PSCustomObject]@{
        TipoVulnerabilidad = "Log4j (CVE-2021-44228)"
        Archivo            = $File.FullName
        Version            = $version
        Estado             = $status
        Detalle            = $detalle
    }
}

function Test-StrutsFile {
    param([System.IO.FileInfo]$File)

    $name   = $File.Name
    $version = $null
    $status  = "Desconocido"
    $detalle = "No se pudo determinar la versión desde el nombre."

    $regex = [regex]'struts2-core-(?<ver>\d+\.\d+(\.\d+)*)\.jar'
    $m = $regex.Match($name)
    if ($m.Success) {
        $versionString = $m.Groups['ver'].Value
        try {
            $v = [version]$versionString
            $version = $versionString

            $vuln12611 = ($v -ge [version]"2.0.0" -and $v -le [version]"2.3.33") -or
                         ($v -ge [version]"2.5.0" -and $v -le [version]"2.5.10.1")

            $vuln11776 = ($v -ge [version]"2.3.0" -and $v -le [version]"2.3.34") -or
                         ($v -ge [version]"2.5.0" -and $v -le [version]"2.5.16")

            if ($vuln12611 -or $vuln11776) {
                $status = "VULNERABLE"
                $detalle = "struts2-core $version afectado. Actualizar a 2.3.35 o 2.5.17+."
            }
            else {
                $status  = "OK"
                $detalle = "struts2-core $version no en rangos vulnerables."
            }
        } catch {
            $status  = "Desconocido"
            $detalle = "No se pudo procesar la versión."
        }
    }

    [PSCustomObject]@{
        TipoVulnerabilidad = "Struts (CVE-2017-12611 / CVE-2018-11776)"
        Archivo            = $File.FullName
        Version            = $version
        Estado             = $status
        Detalle            = $detalle
    }
}

$results = @()

foreach ($path in $Paths) {
    if (-not (Test-Path $path)) { continue }

    try {
        $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue

        foreach ($f in $files) {
            if ($f.Name -like "log4j*.jar") {
                $results += Test-Log4jFile -File $f
            }
            elseif ($f.Name -like "struts2-core*.jar") {
                $results += Test-StrutsFile -File $f
            }
        }
    } catch {}
}

"Reporte de validación de bibliotecas Apache" | Out-File -FilePath $OutputFile -Encoding UTF8
"Servidor: $env:COMPUTERNAME" | Out-File -FilePath $OutputFile -Append
"Fecha: $(Get-Date)" | Out-File -FilePath $OutputFile -Append
"`r`n" | Out-File -FilePath $OutputFile -Append

if ($results.Count -eq 0) {
    "No se encontraron archivos vulnerables en las rutas indicadas." | Out-File -FilePath $OutputFile -Append
} else {
    $results |
        Sort-Object TipoVulnerabilidad, Archivo |
        Format-Table -AutoSize |
        Out-String |
        Out-File -FilePath $OutputFile -Append
}

"Archivo generado: $OutputFile"

