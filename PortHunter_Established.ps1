<#
.SYNOPSIS
    PortHunter - passive local socket inspection (compatibility wrapper).

.DESCRIPTION
    Runs PortHunter.ps1 with -Passive: no connection is opened towards local services (no hidden-port scan, no banner grabbing). Socket, process, signature and firewall analysis only; completes in seconds.
    All parameters are forwarded to PortHunter.ps1 (see Get-Help .\PortHunter.ps1 -Full).

.EXAMPLE
    .\PortHunter_Established.ps1 -SkipUDP -NoPrompt

.NOTES
    PortHunter
    Copyright (C) 2026 Leproide

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program. If not, see <https://www.gnu.org/licenses/>.

    SPDX-License-Identifier: GPL-3.0-or-later
    Author:  https://github.com/Leproide
    Project: https://github.com/Leproide/PortHunter
#>

# Locate the engine next to this wrapper
$engine = Join-Path -Path $PSScriptRoot -ChildPath 'PortHunter.ps1'
if (-not (Test-Path -LiteralPath $engine)) {
    Write-Error "PortHunter.ps1 not found in $PSScriptRoot"
    exit 1
}

# Named parameters in $args are preserved by splatting
& $engine -Passive @args
exit $LASTEXITCODE
