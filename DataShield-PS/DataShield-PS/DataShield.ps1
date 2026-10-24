[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('Scan', 'Baseline', 'Verify')]
    [string]$Action,

    [Parameter(Mandatory = $true, Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [string]$OutputDirectory = '.\DataShield-Reports',
    [string]$BaselinePath,
    [ValidateRange(1, 100)]
    [int]$MaxScanFileSizeMB = 2
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-PathWithin {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$Parent
    )

    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))
    $candidateFull = [System.IO.Path]::GetFullPath($Candidate).TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))

    if ($candidateFull.Equals($parentFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    $prefix = $parentFull + [System.IO.Path]::DirectorySeparatorChar
    return $candidateFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-DataShieldInventory {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$ReportsRoot
    )

    $excludedDirectoryNames = @(
        '.git', 'node_modules', '.venv', 'venv', 'bin', 'obj', 'dist',
        'build', 'coverage', '.next', '.angular', 'packages', 'DataShield-Reports'
    )
    $reportsFull = [System.IO.Path]::GetFullPath($ReportsRoot)
    $rootWithSeparator = [System.IO.Path]::GetFullPath($Root).TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)) + [System.IO.Path]::DirectorySeparatorChar
    $files = New-Object 'System.Collections.Generic.List[object]'
    $directories = New-Object 'System.Collections.Generic.Stack[string]'
    $directories.Push($Root)

    while ($directories.Count -gt 0) {
        $currentDirectory = $directories.Pop()
        $children = Get-ChildItem -LiteralPath $currentDirectory -Force -ErrorAction SilentlyContinue

        foreach ($entry in $children) {
            if ($entry.PSIsContainer) {
                if ($excludedDirectoryNames -contains $entry.Name) { continue }
                if (Test-PathWithin -Candidate $entry.FullName -Parent $reportsFull) { continue }
                $directories.Push($entry.FullName)
            }
            else {
                if (Test-PathWithin -Candidate $entry.FullName -Parent $reportsFull) { continue }
                $full = [System.IO.Path]::GetFullPath($entry.FullName)
                if (-not $full.StartsWith($rootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
                $relativePath = $full.Substring($rootWithSeparator.Length)
                $files.Add([pscustomobject]@{
                    FullName = $full
                    RelativePath = $relativePath
                    Length = [long]$entry.Length
                })
            }
        }
    }

    return $files.ToArray()
}

function Write-JsonReport {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $json = ConvertTo-Json -InputObject $Object -Depth 8
    Set-Content -LiteralPath $Destination -Value $json -Encoding UTF8
}

function Get-TextRules {
    return @(
        [pscustomobject]@{
            Name = 'PrivateKeyBlock'; Category = 'Clave criptográfica privada'; Severity = 'Critical'
            Regex = [regex]::new('-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        },
        [pscustomobject]@{
            Name = 'AwsAccessKeyId'; Category = 'Credencial de nube'; Severity = 'High'
            Regex = [regex]::new('\bAKIA[0-9A-Z]{16}\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        },
        [pscustomobject]@{
            Name = 'CredentialAssignment'; Category = 'Posible secreto en código'; Severity = 'High'
            Regex = [regex]::new('\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*["'']?[^\s"'',;]{8,}', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        },
        [pscustomobject]@{
            Name = 'JwtLikeToken'; Category = 'Token con formato JWT'; Severity = 'High'
            Regex = [regex]::new('\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b', [System.Text.RegularExpressions.RegexOptions]::None)
        },
        [pscustomobject]@{
            Name = 'EmailAddress'; Category = 'Posible dato personal: correo'; Severity = 'Medium'
            Regex = [regex]::new('\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        },
        [pscustomobject]@{
            Name = 'PeruMobileNumber'; Category = 'Posible dato personal: teléfono'; Severity = 'Medium'
            Regex = [regex]::new('(?<!\d)(?:\+?51[\s.-]?)?9\d{2}[\s.-]?\d{3}[\s.-]?\d{3}(?!\d)', [System.Text.RegularExpressions.RegexOptions]::None)
        },
        [pscustomobject]@{
            Name = 'PeruDniWithLabel'; Category = 'Posible dato personal: DNI'; Severity = 'High'
            Regex = [regex]::new('\b(?:DNI|documento(?:\s+nacional)?(?:\s+de\s+identidad)?)\s*[:#-]?\s*\d{8}\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
    )
}

function Invoke-DataShieldScan {
    param(
        [Parameter(Mandatory = $true)][object[]]$Files,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$ReportsRoot,
        [Parameter(Mandatory = $true)][int]$MaxSizeMB
    )

    $textExtensions = @(
        '.txt', '.csv', '.tsv', '.json', '.xml', '.log', '.sql', '.ps1', '.psm1',
        '.psd1', '.py', '.js', '.ts', '.html', '.htm', '.md', '.yaml', '.yml',
        '.config', '.ini', '.env', '.properties', '.php', '.java', '.cs', '.rb', '.go'
    )
    $maxBytes = [long]$MaxSizeMB * 1MB
    $rules = @(Get-TextRules)
    $findings = New-Object 'System.Collections.Generic.List[object]'
    $processedFiles = 0
    $skippedLargeFiles = 0
    $candidateFiles = @($Files | Where-Object { $textExtensions -contains [System.IO.Path]::GetExtension($_.FullName).ToLowerInvariant() })
    $total = $candidateFiles.Count

    for ($index = 0; $index -lt $total; $index++) {
        $file = $candidateFiles[$index]
        if ($file.Length -gt $maxBytes) {
            $skippedLargeFiles++
            continue
        }

        $processedFiles++
        $lineNumber = 0
        $reader = $null
        try {
            $reader = [System.IO.File]::OpenText($file.FullName)
            while (($line = $reader.ReadLine()) -ne $null) {
                $lineNumber++
                foreach ($rule in $rules) {
                    if ($rule.Regex.IsMatch($line)) {
                        # Intentionally do not include matched content or the line itself in reports.
                        $findings.Add([pscustomobject]@{
                            RelativePath = $file.RelativePath
                            Line = $lineNumber
                            Severity = $rule.Severity
                            Category = $rule.Category
                            Rule = $rule.Name
                        })
                    }
                }
            }
        }
        catch {
            Write-Warning ("No se pudo analizar '{0}': {1}" -f $file.RelativePath, $_.Exception.Message)
        }
        finally {
            if ($null -ne $reader) { $reader.Dispose() }
        }

        if (($index % 25) -eq 0 -and $total -gt 0) {
            $percent = [int](($index + 1) * 100 / $total)
            Write-Progress -Activity 'DataShield: analizando posibles datos sensibles' -Status ("{0} de {1} archivos" -f ($index + 1), $total) -PercentComplete $percent
        }
    }
    Write-Progress -Activity 'DataShield: analizando posibles datos sensibles' -Completed

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $csvPath = Join-Path $ReportsRoot ("scan-{0}.csv" -f $stamp)
    $jsonPath = Join-Path $ReportsRoot ("scan-{0}.json" -f $stamp)
    $findingArray = $findings.ToArray()

    if ($findingArray.Count -gt 0) {
        $findingArray | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    }
    else {
        '"RelativePath","Line","Severity","Category","Rule"' | Set-Content -LiteralPath $csvPath -Encoding UTF8
    }

    $report = [pscustomobject]@{
        Tool = 'DataShield-PS'
        Action = 'Scan'
        GeneratedAt = (Get-Date).ToString('o')
        RootLabel = (Split-Path -Leaf $Root)
        SupportedTextFilesFound = $total
        FilesScanned = $processedFiles
        LargeFilesSkipped = $skippedLargeFiles
        FindingCount = $findingArray.Count
        Findings = @($findingArray)
        Note = 'Se reportan categorías y ubicaciones; no se guardan los valores coincidentes ni fragmentos del contenido.'
    }
    Write-JsonReport -Object $report -Destination $jsonPath

    Write-Host ''
    Write-Host 'DataShield: escaneo completado.' -ForegroundColor Green
    Write-Host ("Archivos de texto analizados: {0}" -f $processedFiles)
    Write-Host ("Archivos grandes omitidos (>{0} MB): {1}" -f $MaxSizeMB, $skippedLargeFiles)
    Write-Host ("Coincidencias heurísticas: {0}" -f $findingArray.Count)
    Write-Host ("Reporte CSV: {0}" -f $csvPath)
    Write-Host ("Reporte JSON: {0}" -f $jsonPath)
    Write-Host 'Nota: una coincidencia requiere revisión humana y no confirma por sí sola una exposición.' -ForegroundColor Yellow
}

function New-DataShieldBaseline {
    param(
        [Parameter(Mandatory = $true)][object[]]$Files,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $entries = New-Object 'System.Collections.Generic.List[object]'
    $total = $Files.Count
    for ($index = 0; $index -lt $total; $index++) {
        $file = $Files[$index]
        try {
            $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
            $entries.Add([pscustomobject]@{
                RelativePath = $file.RelativePath
                Length = $file.Length
                SHA256 = $hash
            })
        }
        catch {
            Write-Warning ("No se pudo calcular el hash de '{0}': {1}" -f $file.RelativePath, $_.Exception.Message)
        }

        if (($index % 50) -eq 0 -and $total -gt 0) {
            $percent = [int](($index + 1) * 100 / $total)
            Write-Progress -Activity 'DataShield: creando línea base de integridad' -Status ("{0} de {1} archivos" -f ($index + 1), $total) -PercentComplete $percent
        }
    }
    Write-Progress -Activity 'DataShield: creando línea base de integridad' -Completed

    $baseline = [pscustomobject]@{
        Tool = 'DataShield-PS'
        SchemaVersion = 1
        CreatedAt = (Get-Date).ToString('o')
        RootLabel = (Split-Path -Leaf $Root)
        Algorithm = 'SHA256'
        FileCount = $entries.Count
        Files = @($entries.ToArray())
    }
    Write-JsonReport -Object $baseline -Destination $Destination
    Write-Host ''
    Write-Host 'Línea base creada.' -ForegroundColor Green
    Write-Host ("Archivos registrados: {0}" -f $entries.Count)
    Write-Host ("Archivo: {0}" -f $Destination)
    Write-Host 'Guarda la línea base en una ubicación protegida y genera una nueva solo tras validar cambios legítimos.' -ForegroundColor Yellow
}

function Compare-DataShieldBaseline {
    param(
        [Parameter(Mandatory = $true)][object[]]$Files,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$ReportsRoot,
        [Parameter(Mandatory = $true)][string]$BaselineFile
    )

    if (-not (Test-Path -LiteralPath $BaselineFile -PathType Leaf)) {
        throw "No se encontró la línea base: $BaselineFile. Ejecuta primero -Action Baseline."
    }

    $baseline = Get-Content -LiteralPath $BaselineFile -Raw | ConvertFrom-Json
    if ($baseline.Tool -ne 'DataShield-PS' -or $baseline.SchemaVersion -ne 1) {
        throw 'El archivo de línea base no corresponde a un formato DataShield-PS compatible.'
    }

    $baselineByPath = @{}
    foreach ($entry in @($baseline.Files)) { $baselineByPath[[string]$entry.RelativePath] = $entry }

    $currentByPath = @{}
    foreach ($file in $Files) {
        try {
            $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
            $currentByPath[[string]$file.RelativePath] = [pscustomobject]@{
                RelativePath = $file.RelativePath
                Length = $file.Length
                SHA256 = $hash
            }
        }
        catch {
            Write-Warning ("No se pudo verificar '{0}': {1}" -f $file.RelativePath, $_.Exception.Message)
        }
    }

    $changes = New-Object 'System.Collections.Generic.List[object]'
    foreach ($pathKey in $currentByPath.Keys) {
        $current = $currentByPath[$pathKey]
        if (-not $baselineByPath.ContainsKey($pathKey)) {
            $changes.Add([pscustomobject]@{ RelativePath = $pathKey; Status = 'Added'; PreviousSHA256 = ''; CurrentSHA256 = $current.SHA256 })
        }
        elseif ($baselineByPath[$pathKey].SHA256 -ne $current.SHA256) {
            $changes.Add([pscustomobject]@{ RelativePath = $pathKey; Status = 'Modified'; PreviousSHA256 = $baselineByPath[$pathKey].SHA256; CurrentSHA256 = $current.SHA256 })
        }
    }

    foreach ($pathKey in $baselineByPath.Keys) {
        if (-not $currentByPath.ContainsKey($pathKey)) {
            $changes.Add([pscustomobject]@{ RelativePath = $pathKey; Status = 'Removed'; PreviousSHA256 = $baselineByPath[$pathKey].SHA256; CurrentSHA256 = '' })
        }
    }

    $changeArray = @($changes.ToArray() | Sort-Object Status, RelativePath)
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $csvPath = Join-Path $ReportsRoot ("integrity-{0}.csv" -f $stamp)
    $jsonPath = Join-Path $ReportsRoot ("integrity-{0}.json" -f $stamp)

    if ($changeArray.Count -gt 0) {
        $changeArray | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    }
    else {
        '"RelativePath","Status","PreviousSHA256","CurrentSHA256"' | Set-Content -LiteralPath $csvPath -Encoding UTF8
    }

    $summary = [pscustomobject]@{
        Tool = 'DataShield-PS'
        Action = 'Verify'
        GeneratedAt = (Get-Date).ToString('o')
        RootLabel = (Split-Path -Leaf $Root)
        BaselineCreatedAt = $baseline.CreatedAt
        BaselineFileCount = @($baseline.Files).Count
        CurrentFileCount = $currentByPath.Count
        AddedCount = @($changeArray | Where-Object Status -eq 'Added').Count
        ModifiedCount = @($changeArray | Where-Object Status -eq 'Modified').Count
        RemovedCount = @($changeArray | Where-Object Status -eq 'Removed').Count
        Changes = @($changeArray)
    }
    Write-JsonReport -Object $summary -Destination $jsonPath

    Write-Host ''
    if ($changeArray.Count -eq 0) {
        Write-Host 'Verificación completada: no se detectaron cambios respecto a la línea base.' -ForegroundColor Green
    }
    else {
        Write-Host 'Verificación completada: se detectaron diferencias que deben revisarse.' -ForegroundColor Yellow
        Write-Host ("Agregados: {0} | Modificados: {1} | Eliminados: {2}" -f $summary.AddedCount, $summary.ModifiedCount, $summary.RemovedCount)
    }
    Write-Host ("Reporte CSV: {0}" -f $csvPath)
    Write-Host ("Reporte JSON: {0}" -f $jsonPath)
}

try {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "La ruta de análisis no existe o no es una carpeta: $Path"
    }
    $rootPath = (Resolve-Path -LiteralPath $Path).Path
    $reportsPath = [System.IO.Path]::GetFullPath($OutputDirectory)

    if ((Test-PathWithin -Candidate $reportsPath -Parent $rootPath) -and
        (Test-PathWithin -Candidate $rootPath -Parent $reportsPath)) {
        throw 'La carpeta de reportes no puede ser la misma que la carpeta analizada.'
    }
    if ((Test-PathWithin -Candidate $rootPath -Parent $reportsPath) -and
        -not $reportsPath.Equals($rootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'La carpeta de reportes no debe ser una carpeta superior que contenga la ruta analizada. Usa una carpeta de reportes separada.'
    }

    if (-not (Test-Path -LiteralPath $reportsPath -PathType Container)) {
        New-Item -ItemType Directory -Path $reportsPath -Force | Out-Null
    }

    if ([string]::IsNullOrWhiteSpace($BaselinePath)) {
        $baselineFullPath = Join-Path $reportsPath 'baseline.json'
    }
    else {
        $baselineFullPath = [System.IO.Path]::GetFullPath($BaselinePath)
    }

    $inventory = @(Get-DataShieldInventory -Root $rootPath -ReportsRoot $reportsPath)
    Write-Host ("DataShield-PS | Acción: {0} | Archivos inventariados: {1}" -f $Action, $inventory.Count) -ForegroundColor Cyan

    switch ($Action) {
        'Scan' {
            Invoke-DataShieldScan -Files $inventory -Root $rootPath -ReportsRoot $reportsPath -MaxSizeMB $MaxScanFileSizeMB
        }
        'Baseline' {
            New-DataShieldBaseline -Files $inventory -Root $rootPath -Destination $baselineFullPath
        }
        'Verify' {
            Compare-DataShieldBaseline -Files $inventory -Root $rootPath -ReportsRoot $reportsPath -BaselineFile $baselineFullPath
        }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
