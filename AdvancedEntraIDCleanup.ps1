<#
.SYNOPSIS
    Diagnostic script to trace service account usage across Microsoft 365 services
.DESCRIPTION
    Checks multiple locations where a service account might be configured or have permissions
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ServiceAccountUPN = "CCGlobal_Micro_Solutions_pty_ltdRosebank@globalmicro.co.za"
)

# Connect to required services
Write-Host "Connecting to Microsoft services..." -ForegroundColor Yellow
Connect-MgGraph -Scopes "User.Read.All","Application.Read.All","Directory.Read.All","Group.Read.All","AuditLog.Read.All","Policy.Read.All"
Connect-ExchangeOnline -ShowBanner:$false

Write-Host "`n=== CHECKING SERVICE ACCOUNT USAGE ===" -ForegroundColor Cyan
Write-Host "Account: $ServiceAccountUPN" -ForegroundColor Cyan

# 1. Check basic account properties
Write-Host "`n[1] Account Properties:" -ForegroundColor Green
$user = Get-MgUser -UserId $ServiceAccountUPN -Property * -ErrorAction SilentlyContinue
if ($user) {
    Write-Host "  - Display Name: $($user.DisplayName)"
    Write-Host "  - Account Enabled: $($user.AccountEnabled)"
    Write-Host "  - Created: $($user.CreatedDateTime)"
    Write-Host "  - User Type: $($user.UserType)"
    Write-Host "  - Licenses: $(($user.AssignedLicenses | ForEach-Object { $_.SkuId }) -join ', ')"
} else {
    Write-Host "  - Account not found!" -ForegroundColor Red
}

# 2. Check group memberships
Write-Host "`n[2] Group Memberships:" -ForegroundColor Green
$groups = Get-MgUserMemberOf -UserId $ServiceAccountUPN -All -ErrorAction SilentlyContinue
if ($groups) {
    foreach ($group in $groups) {
        $groupDetails = Get-MgGroup -GroupId $group.Id -ErrorAction SilentlyContinue
        Write-Host "  - $($groupDetails.DisplayName) (Type: $($groupDetails.GroupTypes -join ','))"
    }
} else {
    Write-Host "  - No group memberships found"
}

# 3. Check Teams policies
Write-Host "`n[3] Teams Policies & Configuration:" -ForegroundColor Green
try {
    # This requires Teams PowerShell module
    if (Get-Module -ListAvailable -Name MicrosoftTeams) {
        Connect-MicrosoftTeams
        $teamsPolicies = Get-CsOnlineUser -Identity $ServiceAccountUPN -ErrorAction SilentlyContinue
        if ($teamsPolicies) {
            Write-Host "  - Teams Calling Policy: $($teamsPolicies.TeamsCallingPolicy)"
            Write-Host "  - Teams Meeting Policy: $($teamsPolicies.TeamsMeetingPolicy)"
            Write-Host "  - Teams Recording Policy: $($teamsPolicies.TeamsComplianceRecordingPolicy)"
            Write-Host "  - Application Instance: $($teamsPolicies.IsApplicationInstance)"
        }
    } else {
        Write-Host "  - Teams PowerShell module not installed" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  - Could not retrieve Teams policies: $_" -ForegroundColor Yellow
}

# 4. Check for application/service principal associations
Write-Host "`n[4] Service Principal/App Registrations:" -ForegroundColor Green
$servicePrincipals = Get-MgServicePrincipal -All | Where-Object { 
    $_.DisplayName -like "*Call*Cabinet*" -or 
    $_.DisplayName -like "*recording*" -or
    $_.AppId -eq $user.Id
}
foreach ($sp in $servicePrincipals) {
    Write-Host "  - App: $($sp.DisplayName)"
    Write-Host "    App ID: $($sp.AppId)"
    Write-Host "    Object ID: $($sp.Id)"
}

# 5. Check mailbox permissions (delegated access)
Write-Host "`n[5] Mailbox Permissions:" -ForegroundColor Green
try {
    # Check who has access TO this mailbox
    $mailboxPerms = Get-EXOMailboxPermission -Identity $ServiceAccountUPN -ErrorAction SilentlyContinue
    if ($mailboxPerms) {
        Write-Host "  Accounts with access to this mailbox:"
        $mailboxPerms | Where-Object { $_.User -ne "NT AUTHORITY\SELF" } | ForEach-Object {
            Write-Host "    - $($_.User) : $($_.AccessRights -join ', ')"
        }
    }
    
    # Check what mailboxes this account has access TO
    $recipientPerms = Get-EXORecipientPermission -Trustee $ServiceAccountUPN -ErrorAction SilentlyContinue
    if ($recipientPerms) {
        Write-Host "  This account has access to:"
        $recipientPerms | ForEach-Object {
            Write-Host "    - $($_.Identity) : $($_.AccessRights -join ', ')"
        }
    }
} catch {
    Write-Host "  - Could not check mailbox permissions: $_" -ForegroundColor Yellow
}

# 6. Check for OAuth app permissions
Write-Host "`n[6] OAuth2 Permission Grants:" -ForegroundColor Green
$oauth2Grants = Get-MgOauth2PermissionGrant -All | Where-Object { 
    $_.PrincipalId -eq $user.Id -or $_.ConsentType -eq "AllPrincipals" 
}
foreach ($grant in $oauth2Grants) {
    $app = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId -ErrorAction SilentlyContinue
    Write-Host "  - App: $($app.DisplayName)"
    Write-Host "    Scope: $($grant.Scope)"
    Write-Host "    Consent Type: $($grant.ConsentType)"
}

# 7. Check recent sign-in activity
Write-Host "`n[7] Recent Activity (Last 30 days):" -ForegroundColor Green
$startDate = (Get-Date).AddDays(-30).ToString("yyyy-MM-dd")
try {
    $signIns = Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$ServiceAccountUPN' and createdDateTime ge $startDate" -Top 10
    if ($signIns) {
        foreach ($signIn in $signIns) {
            Write-Host "  - $($signIn.CreatedDateTime): $($signIn.AppDisplayName) - $($signIn.Status.ErrorCode)"
        }
    } else {
        Write-Host "  - No sign-in activity found"
    }
} catch {
    Write-Host "  - Could not retrieve sign-in logs: $_" -ForegroundColor Yellow
}

# 8. Check for Compliance Recording Policies (Teams)
Write-Host "`n[8] Teams Compliance Recording Applications:" -ForegroundColor Green
try {
    if (Get-Command Get-CsTeamsComplianceRecordingPolicy -ErrorAction SilentlyContinue) {
        $recordingPolicies = Get-CsTeamsComplianceRecordingPolicy
        foreach ($policy in $recordingPolicies) {
            if ($policy.ComplianceRecordingApplications) {
                Write-Host "  Policy: $($policy.Identity)"
                foreach ($app in $policy.ComplianceRecordingApplications) {
                    Write-Host "    - App ID: $($app.Id)"
                    Write-Host "    - Required During Call: $($app.RequiredDuringCall)"
                    Write-Host "    - Required During Meeting: $($app.RequiredDuringMeeting)"
                }
            }
        }
    }
} catch {
    Write-Host "  - Could not check compliance recording policies" -ForegroundColor Yellow
}

# 9. Search audit logs for any activity
Write-Host "`n[9] Audit Log Activity (Last 7 days):" -ForegroundColor Green
$auditStartDate = (Get-Date).AddDays(-7).ToString("yyyy-MM-dd")
try {
    $auditLogs = Get-MgAuditLogDirectoryAudit -Filter "initiatedBy/user/userPrincipalName eq '$ServiceAccountUPN' or targetResources/any(t: t/userPrincipalName eq '$ServiceAccountUPN')" -Top 20
    if ($auditLogs) {
        foreach ($log in $auditLogs) {
            Write-Host "  - $($log.ActivityDateTime): $($log.ActivityDisplayName)"
        }
    } else {
        Write-Host "  - No audit log activity found"
    }
} catch {
    Write-Host "  - Could not retrieve audit logs: $_" -ForegroundColor Yellow
}

Write-Host "`n=== RECOMMENDATIONS ===" -ForegroundColor Cyan
Write-Host "1. If this is a Call Cabinet service account, check:"
Write-Host "   - Teams Admin Centre> Voice > Compliance Recording"
Write-Host "   - Look for any recording bots or applications"
Write-Host "2. Contact Call Cabinet support with the App IDs found above"
Write-Host "3. Check if the account needs to be converted to an Application Instance"
Write-Host "   (Resource accounts for Teams recording typically should be application instances)"

# Disconnect sessions
Disconnect-MgGraph -ErrorAction SilentlyContinue
Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
