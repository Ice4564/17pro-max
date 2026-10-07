"""Interactive menu: Thai-aware layout and navigation."""

import builtins

from sleuth import menu


def test_thai_width_ignores_marks():
    assert menu.width("เว็บ") == 3          # ็ and ์-style marks take no column
    assert menu.width("\033[1mabc\033[0m") == 3
    assert menu.width(menu.pad("อีเมล", 7)) == 7


def test_every_menu_row_fits_the_box():
    inner = menu.BOX_WIDTH - 2
    for key, name, desc in menu.MENU:
        assert menu.width(f"  [{key}]  {menu.pad(name, 7)}{desc}") <= inner
    for line in menu.box(["สวัสดี", "x"], "เมนูหลัก").splitlines():
        assert menu.width(line) == menu.BOX_WIDTH + 2


def test_navigation(monkeypatch, capsys):
    answers = iter(["9", "", "4", "not-an-email", "", "0"])
    prompts = []

    def fake_input(prompt=""):
        prompts.append(prompt)
        return next(answers)

    monkeypatch.setattr(builtins, "input", fake_input)
    called = []
    monkeypatch.setattr(menu, "run_scan_cli", lambda args: called.append(args.scan))
    assert menu.run_menu(type("A", (), {})(), [], []) == 0
    out = capsys.readouterr().out + "".join(prompts)
    assert "ไม่มีตัวเลือก" in out and "ดูไม่เหมือนอีเมล" in out
    assert called == []                      # bad email, then Enter = back to menu
