"""AuthLab self-check: seeds fire in vuln mode only, negative controls hold in both."""


def test_ground_truth(labs, lab_checks):
    vuln, hard = lab_checks(labs["vuln"]), lab_checks(labs["hardened"])
    assert vuln and hard
    for key, fired in vuln.items():
        if key.startswith("AL-"):
            assert fired, f"{key} did not fire in vuln mode"
            assert not hard[key], f"{key} still fires in hardened mode (control broken)"
        else:
            assert fired and hard[key], f"{key} negative control broken (vuln={fired})"
