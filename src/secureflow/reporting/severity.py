from cvss import CVSS3, CVSS4


def score_to_severity(score: float) -> str:
    if score == 0:
        return "info"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def cvss_vector_to_severity(vector: str) -> str:
    try:
        if vector.startswith("CVSS:4.0/"):
            score = CVSS4(vector).scores()[0]
        elif vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
            score = CVSS3(vector).scores()[0]
        else:
            return "unknown"

        return score_to_severity(score)

    except (ValueError, KeyError, TypeError):
        return "unknown"
