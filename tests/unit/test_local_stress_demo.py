import local_stress_demo as demo


def test_all_local_scenarios_hold():
    results = demo.run_all()
    assert [r.id for r in results] == [f"A{i}" for i in range(1, 13)]
    assert [r.id for r in results if not r.held] == []


def test_no_blocked_scenario_reaches_the_executor():
    calls = {r.id: r.executor_calls for r in demo.run_all()}
    assert calls["A5"] == 1  # the single legitimate approved stop
    assert calls["A9"] == demo.RISK_BUDGET  # reads inside the budget
    assert calls["A12"] == 1  # the one legitimate read
    assert all(n == 0 for k, n in calls.items() if k not in {"A5", "A9", "A12"})
