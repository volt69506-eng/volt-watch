"""TDD: only report a missing boot preset when the boot flow is preset-driven (#48)."""

from volt_watch import collector
from volt_watch.checks import boot_preset_check
from volt_watch.severity import Severity


def _flow(**overrides):
    flow = {
        "bootloader": "limine",
        "preset_driven": True,
        "explicit_args": False,
        "kernels": ["linux-omarchy"],
        "presets": ["linux-omarchy"],
        "preset_dir": "/etc/mkinitcpio.d",
    }
    flow.update(overrides)
    return flow


def _script(tmp_path, name, text):
    path = tmp_path / "scripts" / name
    path.parent.mkdir(exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_collector_detects_explicit_argument_builder(tmp_path):
    _script(
        tmp_path, "limine-mkinitcpio-install",
        'args=(--kernel "$ver" --generate /boot/uki)\n/usr/bin/mkinitcpio "${args[@]}"\n',
    )
    boot = tmp_path / "boot"
    boot.mkdir()
    (boot / "limine.cfg").write_text("DEFAULT_ENTRY=1\n", encoding="utf-8")

    flow = collector.boot_flow(
        script_dirs=(str(tmp_path / "scripts"),),
        boot_dir=str(boot),
        preset_dir=str(tmp_path / "mkinitcpio.d"),
        kernel_packages=["linux-omarchy"],
    )

    assert flow["bootloader"] == "limine"
    assert flow["explicit_args"] is True
    assert flow["preset_driven"] is False
    assert flow["kernels"] == ["linux-omarchy"]


def test_collector_detects_preset_driven_hook(tmp_path):
    _script(tmp_path, "90-mkinitcpio.hook", "Exec = /usr/bin/mkinitcpio -P\n")
    boot = tmp_path / "boot"
    boot.mkdir()
    (boot / "grub").mkdir()
    (boot / "grub" / "grub.cfg").write_text("# generated\n", encoding="utf-8")
    presets = tmp_path / "mkinitcpio.d"
    presets.mkdir()
    (presets / "linux.preset").write_text("PRESET_DEFAULTS\n", encoding="utf-8")

    flow = collector.boot_flow(
        script_dirs=(str(tmp_path / "scripts"),),
        boot_dir=str(boot),
        preset_dir=str(presets),
        kernel_packages=["linux", "linux-lts"],
    )

    assert flow["bootloader"] == "grub"
    assert flow["preset_driven"] is True
    assert flow["explicit_args"] is False
    assert flow["presets"] == ["linux"]


def test_collector_without_a_recognised_bootloader_says_unknown(tmp_path):
    flow = collector.boot_flow(
        script_dirs=(str(tmp_path / "empty-scripts"),),
        boot_dir=str(tmp_path / "empty-boot"),
        preset_dir=str(tmp_path / "empty-presets"),
        kernel_packages=[],
    )

    assert flow["bootloader"] is None
    assert flow["preset_driven"] is None


def test_explicit_argument_builder_reports_nothing():
    assert boot_preset_check(_flow(explicit_args=True, presets=[], kernels=["linux-omarchy"])) == []


def test_no_known_bootloader_reports_nothing():
    assert boot_preset_check(_flow(bootloader=None, presets=[], kernels=["linux-omarchy"])) == []


def test_unknown_flow_reports_nothing():
    assert boot_preset_check(None) == []


def test_preset_driven_flow_names_the_kernel_without_a_preset():
    findings = boot_preset_check(_flow(
        kernels=["linux-omarchy", "linux-lts"],
        presets=["linux-omarchy"],
    ))

    assert [f.check for f in findings] == ["boot.preset_missing"]
    assert findings[0].severity is Severity.WARNING
    assert "linux-lts" in findings[0].message
    assert findings[0].evidence == {
        "kernel": "linux-lts",
        "path": "/etc/mkinitcpio.d/linux-lts.preset",
    }


def test_preset_driven_flow_with_all_presets_is_clean():
    assert boot_preset_check(_flow(
        kernels=["linux-omarchy", "linux-lts"],
        presets=["linux-omarchy", "linux-lts"],
    )) == []
