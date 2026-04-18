"""CVSS 4.0 Calculator - Calculate accurate vulnerability scores."""

from typing import Any


class CVSS4Calculator:
    """Calculate CVSS 4.0 scores for vulnerabilities."""

    # CVSS 4.0 Metric values
    ATTACK_VECTOR = {"Network": 0.0, "Adjacent": 0.1, "Local": 0.2, "Physical": 0.3}
    ATTACK_COMPLEXITY = {"Low": 0.0, "High": 0.1}
    PRIVILEGES_REQUIRED = {"None": 0.0, "Low": 0.1, "High": 0.2}
    USER_INTERACTION = {"None": 0.0, "Passive": 0.1, "Active": 0.2}

    CONFIDENTIALITY = {"High": 0.0, "Low": 0.1, "None": 0.2}
    INTEGRITY = {"High": 0.0, "Low": 0.1, "None": 0.2}
    AVAILABILITY = {"High": 0.0, "Low": 0.1, "None": 0.2}

    @classmethod
    def calculate(
        cls,
        attack_vector: str = "Network",
        attack_complexity: str = "Low",
        privileges_required: str = "None",
        user_interaction: str = "None",
        confidentiality: str = "High",
        integrity: str = "High",
        availability: str = "High",
    ) -> dict[str, Any]:
        """
        Calculate CVSS 4.0 score.

        Returns dict with score, severity, and vector string.
        """
        # Calculate Base Score
        base_score = cls._calculate_base_score(
            attack_vector,
            attack_complexity,
            privileges_required,
            user_interaction,
            confidentiality,
            integrity,
            availability,
        )

        # Determine severity rating
        severity = cls._get_severity_rating(base_score)

        # Build vector string
        vector = cls._build_vector_string(
            attack_vector,
            attack_complexity,
            privileges_required,
            user_interaction,
            confidentiality,
            integrity,
            availability,
        )

        return {
            "score": base_score,
            "severity": severity,
            "vector": vector,
            "metrics": {
                "AV": attack_vector,
                "AC": attack_complexity,
                "PR": privileges_required,
                "UI": user_interaction,
                "C": confidentiality,
                "I": integrity,
                "A": availability,
            },
        }

    @classmethod
    def _calculate_base_score(
        cls, av: str, ac: str, pr: str, ui: str, c: str, i: str, a: str
    ) -> float:
        """Calculate base score from metrics."""
        # Impact subscore
        impact = (
            (1 - cls.CONFIDENTIALITY.get(c, 0.2))
            * (1 - cls.INTEGRITY.get(i, 0.2))
            * (1 - cls.AVAILABILITY.get(a, 0.2))
        )
        impact_score = 1 - impact

        # Exploitability subscore
        exploitability = (
            (1 - cls.ATTACK_VECTOR.get(av, 0.0))
            * (1 - cls.ATTACK_COMPLEXITY.get(ac, 0.1))
            * (1 - cls.PRIVILEGES_REQUIRED.get(pr, 0.0))
            * (1 - cls.USER_INTERACTION.get(ui, 0.0))
        )
        exploitability_score = 1 - exploitability

        # Combined score
        if impact_score == 0:
            return 0.0

        base_score = min(10.0, round(impact_score * exploitability_score * 10, 1))

        return base_score

    @classmethod
    def _get_severity_rating(cls, score: float) -> str:
        """Get severity rating from score."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 0.1:
            return "LOW"
        else:
            return "NONE"

    @classmethod
    def _build_vector_string(
        cls, av: str, ac: str, pr: str, ui: str, c: str, i: str, a: str
    ) -> str:
        """Build CVSS 4.0 vector string."""
        return (
            f"CVSS:4.0/AV:{av[0]}/AC:{ac[0]}/PR:{pr[0]}/UI:{ui[0]}/"
            f"C:{c[0]}/I:{i[0]}/A:{a[0]}"
        )

    @classmethod
    def from_vulnerability_type(
        cls, vuln_type: str, context: dict = None
    ) -> dict[str, Any]:
        """Calculate CVSS score based on vulnerability type."""
        vuln_profiles = {
            "idor": {
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "Low",
                "user_interaction": "None",
                "confidentiality": "High",
                "integrity": "Low",
                "availability": "None",
            },
            "sql_injection": {
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "user_interaction": "None",
                "confidentiality": "High",
                "integrity": "High",
                "availability": "High",
            },
            "xss": {
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "user_interaction": "Passive",
                "confidentiality": "Low",
                "integrity": "Low",
                "availability": "None",
            },
            "ssrf": {
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "user_interaction": "None",
                "confidentiality": "High",
                "integrity": "Low",
                "availability": "Low",
            },
            "command_injection": {
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "user_interaction": "None",
                "confidentiality": "High",
                "integrity": "High",
                "availability": "High",
            },
            "auth_bypass": {
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "user_interaction": "None",
                "confidentiality": "High",
                "integrity": "High",
                "availability": "None",
            },
            "misconfiguration": {
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "user_interaction": "None",
                "confidentiality": "Low",
                "integrity": "None",
                "availability": "None",
            },
            "business_logic": {
                "attack_vector": "Network",
                "attack_complexity": "High",
                "privileges_required": "Low",
                "user_interaction": "None",
                "confidentiality": "Low",
                "integrity": "High",
                "availability": "Low",
            },
        }

        metrics = vuln_profiles.get(
            vuln_type.lower(), vuln_profiles["misconfiguration"]
        )

        if context:
            metrics.update(context.get("cvss_overrides", {}))

        return cls.calculate(**metrics)
