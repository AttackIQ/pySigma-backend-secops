import pytest

from sigma.backends.secops import SecOpsBackend
from sigma.collection import SigmaRule
from sigma.pipelines.secops import secops_udm_pipeline


@pytest.fixture
def secops_backend():
    return SecOpsBackend(processing_pipeline=secops_udm_pipeline(prepend_metadata=False))


def test_secops_and_expression(secops_backend: SecOpsBackend):
    assert secops_backend.convert_rule(
        SigmaRule.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: valueA
                    User: valueB
                condition: sel
        """
        )
    ) == ['target.process.command_line = "valueA" nocase AND target.user.userid = "valueB" nocase']


def test_secops_or_expression(secops_backend: SecOpsBackend):
    assert secops_backend.convert_rule(
        SigmaRule.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel1:
                    CommandLine: valueA
                sel2:
                    User: valueB
                condition: 1 of sel*
        """
        )
    ) == ['target.process.command_line = "valueA" nocase OR target.user.userid = "valueB" nocase']


def test_secops_or_expression_parens(secops_backend: SecOpsBackend):
    assert secops_backend.convert_rule(
        SigmaRule.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel1:
                    CommandLine: valueA
                    Image: cmd.exe
                sel2:
                    User: valueB
                condition: 1 of sel*
        """
        )
    ) == [
        '(target.process.command_line = "valueA" nocase AND target.process.file.full_path = "cmd.exe" nocase) OR target.user.userid = "valueB" nocase'
    ]


def test_secops_and_or_expression(secops_backend: SecOpsBackend):
    assert secops_backend.convert_rule(
        SigmaRule.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine:
                        - valueA1
                        - valueA2
                    ProcessId:
                        - valueB1
                        - valueB2
                condition: sel
        """
        )
    ) == ["target.process.command_line = /valueA1|valueA2/ nocase AND target.process.pid = /valueB1|valueB2/ nocase"]


def test_secops_or_and_expression(secops_backend: SecOpsBackend):
    assert secops_backend.convert_rule(
        SigmaRule.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel1:
                    CommandLine: valueA1
                    ProcessId: valueB1
                sel2:
                    CommandLine: valueA2
                    ProcessId: valueB2
                condition: 1 of sel*
        """
        )
    ) == [
        '(target.process.command_line = "valueA1" nocase AND target.process.pid = "valueB1" nocase) OR (target.process.command_line = "valueA2" nocase AND target.process.pid = "valueB2" nocase)'
    ]


def test_secops_in_expression(secops_backend: SecOpsBackend):
    assert secops_backend.convert_rule(
        SigmaRule.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine:
                        - valueA
                        - valueB
                        - valueC
                condition: sel
        """
        )
    ) == ["target.process.command_line = /valueA|valueB|valueC/ nocase"]


def test_secops_regex_query(secops_backend: SecOpsBackend):
    assert secops_backend.convert_rule(
        SigmaRule.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine|re: foo.*bar
                    ProcessId: pid:1234
                condition: sel
        """
        )
    ) == ['target.process.command_line = /foo.*bar/ nocase AND target.process.pid = "pid:1234" nocase']


def test_secops_cidr_query(secops_backend: SecOpsBackend):
    assert secops_backend.convert_rule(
        SigmaRule.from_yaml(
            """
            title: Test
            status: test
            logsource:
                category: network_connection
                product: windows
            detection:
                sel:
                    SourceIp|cidr: 192.168.0.0/16
                condition: sel
        """
        )
    ) == ['net.ip_in_range_cidr(principal.ip, "192.168.0.0/16")']


def test_secops_negation_basic(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                r"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image: '*\process.exe'
                    CommandLine: 'this'
                filter:
                    CommandLine: 'notthis'  
                condition: selection and not filter
        """
            )
        )[0]
        == 'target.process.file.full_path = /\\\\process\\.exe$/ nocase AND target.process.command_line = "this" nocase AND target.process.command_line != "notthis" nocase'
    )


def test_secops_negation_contains(secops_backend: SecOpsBackend):
    assert secops_backend.convert_rule(
        SigmaRule.from_yaml(
            r"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image:
                        - '*\process.exe'
                    CommandLine:
                        - '*this*'
                filter:
                    CommandLine:
                        - '*notthis*'
                condition: selection and not filter
        """
        )
    ) == [
        "target.process.file.full_path = /\\\\process\\.exe$/ nocase AND target.process.command_line = /this/ nocase AND target.process.command_line != /notthis/ nocase"
    ]


def test_secops_grouping(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                r"""
            title: Net connection logic test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    Image:
                        - '*\powershell.exe'
                        - '*\pwsh.exe'
                    CommandLine: 
                        - '*pastebin.com*'
                        - '*anothersite.com*'
                condition: selection
    """
            )
        )[0]
        == "target.process.file.full_path = /\\\\powershell\\.exe|\\\\pwsh\\.exe/ nocase AND target.process.command_line = /pastebin\\.com|anothersite\\.com/ nocase"
    )


def test_secops_escape_cmdline_slash(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                r"""
            title: Delete All Scheduled Tasks
            id: 220457c1-1c9f-4c2e-afe6-9598926222c1
            status: test
            description: Detects the usage of schtasks with the delete flag and the asterisk symbol to delete all tasks from the schedule of the local computer, including tasks scheduled by other users.
            references:
                - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-delete
            author: Nasreddine Bencherchali (Nextron Systems)
            date: 2022-09-09
            tags:
                - attack.impact
                - attack.t1489
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    Image|endswith: '\schtasks.exe'
                    CommandLine|contains|all:
                        - ' /delete '
                        - '/tn \*'
                        - ' /f'
                condition: selection
            falsepositives:
                - Unlikely
            level: high
        """
            )
        )[0]
        == "target.process.file.full_path = /\\\\schtasks\\.exe$/ nocase AND target.process.command_line = / \\/delete / nocase AND target.process.command_line = /\\/tn \\*/ nocase AND target.process.command_line = / \\/f/ nocase"
    )


def test_secops_cmdline_filters(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                r"""
            title: New Firewall Rule Added Via Netsh.EXE
            id: cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c
            status: test
            description: Detects the addition of a new rule to the Windows firewall via netsh
            references:
                - https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf
            author: Markus Neis, Sander Wiebing
            date: 2019-01-29
            modified: 2023-02-10
            tags:
                - attack.defense_evasion
                - attack.t1562.004
                - attack.s0246
            logsource:
                category: process_creation
                product: windows
            detection:
                selection_img:
                    - Image|endswith: '\netsh.exe'
                selection_cli:
                    CommandLine|contains|all:
                        - ' firewall '
                        - ' add '
                filter_optional_dropbox:
                    CommandLine|contains:
                        - 'advfirewall firewall add rule name=Dropbox dir=in action=allow "program=?:\Program Files (x86)\Dropbox\Client\Dropbox.exe" enable=yes profile=Any'
                        - 'advfirewall firewall add rule name=Dropbox dir=in action=allow "program=?:\Program Files\Dropbox\Client\Dropbox.exe" enable=yes profile=Any'
                condition: all of selection_* and not 1 of filter_optional_*
            falsepositives:
                - Legitimate administration activity
                - Software installations
            level: medium
            """
            )
        )[0]
        == 'target.process.file.full_path = /\\\\netsh\\.exe$/ nocase AND target.process.command_line = / firewall / nocase AND target.process.command_line = / add / nocase AND (target.process.command_line != /advfirewall firewall add rule name=Dropbox dir=in action=allow "program=.:\\\\Program Files \\(x86\\)\\\\Dropbox\\\\Client\\\\Dropbox\\.exe" enable=yes profile=Any/ nocase AND target.process.command_line != /advfirewall firewall add rule name=Dropbox dir=in action=allow "program=.:\\\\Program Files\\\\Dropbox\\\\Client\\\\Dropbox\\.exe" enable=yes profile=Any/ nocase)'
    )


def test_secops_yara_l_output_format(secops_backend: SecOpsBackend):
    output = secops_backend.convert_rule(
        SigmaRule.from_yaml(
            r"""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: valueA
                    User: valueB
                condition: sel
            """
        ),
        output_format="yara_l",
    )
    assert "rule test {" in output[0]
    assert "meta:" in output[0]
    assert "events:" in output[0]
    assert "conditions:" in output[0]


def test_secops_or_grouping_regex_escaping(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                r"""
title: Suspicious Dev Tunnel Process
id: 0ef42ab3-e707-490e-ab9e-b0564a72acdc
related:
    - id: b3e6418f-7c7a-4fad-993a-93b65027a9f1
      type: derived
    - id: 9661ec9d-4439-4a7a-abed-d9be4ca43b6d
      type: similar
    - id: 54c8fdd3-6e84-43c4-bb30-25c2e4861bdd
      type: similar
status: stable
description: Rule to detect suspicious devtunnel.exe processes
references:
    - https://blueteamops.medium.com/detecting-dev-tunnels-16f0994dc3e2
    - https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/file/file_event/file_event_win_vscode_tunnel_indicators.yml
author: MBOWER
date: 2023-11-01
tags:
    - attack.t1071.001
    - attack.command-and-control
logsource:
    product: windows
    category: process_creation
detection:
    CommandLine:
        CommandLine|contains:
            - devtunnel
    Image:
        Image|endswith:
            - \devtunnel.exe
    Filter:
        ParentImage|contains:
            - \Teams.exe
            - \devenv.exe
            - \git
            - 'Code Helper (Plugin)'
            - 'GitHub Desktop Helper (Renderer)'
    condition: (CommandLine or Image) and not Filter
falsepositives:
    - Legitimate developer activity
level: medium
    
    """
            )
        )[0]
        == "(target.process.command_line = /devtunnel/ nocase OR target.process.file.full_path = /\\\\devtunnel\\.exe$/ nocase) AND (principal.process.file.full_path != /\\\\Teams\\.exe/ nocase AND principal.process.file.full_path != /\\\\devenv\\.exe/ nocase AND principal.process.file.full_path != /\\\\git/ nocase AND principal.process.file.full_path != /Code Helper \\(Plugin\\)/ nocase AND principal.process.file.full_path != /GitHub Desktop Helper \\(Renderer\\)/ nocase)"
    )


def test_secops_or_filtering(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                r"""
title: Exports Registry Key To a File
id: f0e53e89-8d22-46ea-9db5-9d4796ee2f8a
related:
    - id: 82880171-b475-4201-b811-e9c826cd5eaa
      type: similar
status: test
description: Detects the export of the target Registry key to a file.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Regedit/
    - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
author: Oddvar Moe, Sander Wiebing, oscd.community
date: 2020-10-07
modified: 2024-03-13
tags:
    - attack.exfiltration
    - attack.t1012
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\regedit.exe'
        - OriginalFileName: 'REGEDIT.EXE'
    selection_cli:
        CommandLine|contains: ' -E '
    filter_1:   # filters to avoid intersection with critical keys rule
        CommandLine|contains:
            - 'hklm'
            - 'hkey_local_machine'
    filter_2:
        CommandLine|endswith:
            - '\system'
            - '\sam'
            - '\security'
    condition: all of selection_* and not 1 of filter_*
fields:
    - ParentImage
    - CommandLine
falsepositives:
    - Legitimate export of keys
level: low
                """
            )
        )[0]
        == '(target.process.file.full_path = /\\\\regedit\\.exe$/ nocase OR target.process.file.names = "REGEDIT.EXE" nocase) AND target.process.command_line = / -E / nocase AND ((target.process.command_line != /hklm/ nocase AND target.process.command_line != /hkey_local_machine/ nocase) OR (target.process.command_line != /\\\\system/ nocase AND target.process.command_line != /\\\\sam/ nocase AND target.process.command_line != /\\\\security/ nocase))'
    )
