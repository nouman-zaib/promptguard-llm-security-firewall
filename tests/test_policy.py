from app.security.policy import choose_action, build_security_decision


def test_policy_allow_clean_low_score():
    action = choose_action(score=10, signals=[])
    assert action == "allow"


def test_policy_review_moderate_score():
    action = choose_action(score=45, signals=[])
    assert action == "review"


def test_policy_review_with_rule_signal():
    action = choose_action(score=20, signals=["instruction_override"])
    assert action == "review"


def test_policy_block_high_score():
    action = choose_action(score=75, signals=[])
    assert action == "block"


def test_policy_block_exfiltration_always():
    # Even if numerical score was low, data exfiltration signal forces immediate BLOCK
    action = choose_action(score=15, signals=["possible_data_exfiltration"])
    assert action == "block"


def test_build_security_decision():
    decision = build_security_decision(
        score=95,
        signals=["possible_data_exfiltration"],
        category="data_exfiltration",
        reasons=["Detected credential exfiltration attempt"],
        model_used="nvidia/nemotron-test",
    )
    assert decision.action == "block"
    assert decision.risk_score == 95
    assert "Rule trigger: possible data exfiltration" in decision.reasons
