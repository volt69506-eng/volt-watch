"""Tests for the power-restore register check."""

from volt_watch.checks import power_restore_check


def test_no_finding_when_auto_power_on_is_enabled():
    """Bit 0 clear means the machine powers on when AC returns."""
    assert power_restore_check({"register": 0x08, "present": True}) == []


def test_reports_when_the_machine_would_stay_off():
    findings = power_restore_check({"register": 0x09, "present": True})

    assert [f.check for f in findings] == ["power.restore_disabled"]
    assert findings[0].severity.value == "critical"
    assert "setpci" in findings[0].remedy


def test_reports_when_the_register_cannot_be_read():
    findings = power_restore_check({"register": None, "present": False})

    assert [f.check for f in findings] == ["power.register_missing"]
    assert findings[0].severity.value == "warning"


def test_reports_when_the_boot_unit_is_not_enabled():
    findings = power_restore_check(
        {"register": 0x08, "present": True, "unit_enabled": False}
    )

    assert [f.check for f in findings] == ["power.unit_disabled"]
    assert findings[0].severity.value == "warning"


def test_enabled_and_active_means_no_finding():
    findings = power_restore_check(
        {"register": 0x08, "present": True, "unit_enabled": True, "unit_active": True}
    )

    assert findings == []


def test_an_enabled_unit_that_did_not_run_is_critical():
    """Enabled is not effective: a bad ConditionPathExists or a setpci error
    leaves the unit enabled and the register unwritten."""
    findings = power_restore_check(
        {"register": 0x08, "present": True, "unit_enabled": True, "unit_active": False}
    )

    assert [f.check for f in findings] == ["power.unit_failed"]
    assert findings[0].severity.value == "critical"


def test_an_unknown_active_state_is_not_a_finding():
    findings = power_restore_check(
        {"register": 0x08, "present": True, "unit_enabled": True, "unit_active": None}
    )

    assert findings == []


def test_a_disabled_unit_is_reported_as_disabled_not_failed():
    """Not enabled is the older finding, and it wins: there is nothing to run."""
    findings = power_restore_check(
        {"register": 0x08, "present": True, "unit_enabled": False, "unit_active": False}
    )

    assert [f.check for f in findings] == ["power.unit_disabled"]


def test_a_failed_read_is_not_reported_as_a_disabled_register():
    """setpci prints 0xff when it cannot open the device.

    That is a permission or access failure, not a register value. Reading it
    as 0xff would set bit 0 and raise a false critical finding on every host
    where the auditor runs unprivileged.
    """
    findings = power_restore_check({"register": 0xFF, "present": True})

    assert [f.check for f in findings] == ["power.register_unreadable"]
    assert findings[0].severity.value == "warning"


def test_only_the_exact_failure_marker_is_treated_as_unreadable():
    """0xfe has bit 0 clear and is a real value, not the failure marker."""
    assert power_restore_check({"register": 0xFE, "present": True}) == []
