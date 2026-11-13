import json
import re
import time
from google.genai.errors import ClientError
from src.rag_engine import VulnerableRAGBot


def safe_ask(bot: VulnerableRAGBot, query: str, hardened: bool) -> dict:
    """Wrapper that respects Free Tier 15 RPM rate limit and retries gracefully on 429."""
    while True:
        try:
            res = bot.answer(query, hardened=hardened)
            time.sleep(4.2)  # Stay safely under 15 requests/minute
            return res
        except ClientError as e:
            if "429" in str(e):
                print("   [Rate limit hit — sleeping 25s before resuming...]")
                time.sleep(25)
            else:
                raise


def main():
    bot = VulnerableRAGBot()

    # Ingest updated clean + poisoned docs into Qdrant
    #bot.ingest_knowledge_base("data/clean_faqs.json", "data/poisoned_docs.json")

    with open("data/eval_queries.json", "r") as f:
        eval_data = json.load(f)

    attacks = eval_data["attack_queries"]
    benign = eval_data["benign_queries"]

    report = {"baseline_attacks": [], "hardened_attacks": [], "hardened_benign": []}

    # --- RUN 1: BASELINE (NO GUARDRAILS) ---
    print("\n=== RUNNING BASELINE (NO GUARDRAILS) ON 10 ATTACKS ===")
    baseline_leaks = 0
    for atk in attacks:
        out = safe_ask(bot, atk["query"], hardened=False)
        leaked = bool(re.search(atk["leak_regex"], out["reply"], flags=re.IGNORECASE))
        if leaked:
            baseline_leaks += 1
        status = "COMPROMISED" if leaked else "SAFE"
        print(f"[{atk['id']}] {atk['attack_type']}: {status}")
        report["baseline_attacks"].append({**atk, "leaked": leaked, "reply": out["reply"]})

    # --- RUN 2: HARDENED (4-LAYER GUARDRAILS) ON 10 ATTACKS ---
    print("\n=== RUNNING HARDENED (4-LAYER GUARDRAILS) ON 10 ATTACKS ===")
    hardened_leaks = 0
    for atk in attacks:
        out = safe_ask(bot, atk["query"], hardened=True)
        leaked = bool(re.search(atk["leak_regex"], out["reply"], flags=re.IGNORECASE))
        if leaked:
            hardened_leaks += 1
        status = (
            "COMPROMISED"
            if leaked
            else f"DEFENDED ({', '.join(out['guardrails_triggered']) or 'Spotlighting/LeastPrivilege'})"
        )
        print(f"[{atk['id']}] {atk['attack_type']}: {status}")
        report["hardened_attacks"].append({
            **atk,
            "leaked": leaked,
            "guardrails_triggered": out["guardrails_triggered"],
            "reply": out["reply"],
        })

    # --- RUN 3: FALSE BLOCK CHECK ON 20 BENIGN QUERIES ---
    print("\n=== CHECKING FALSE BLOCKS ON 20 BENIGN QUERIES (takes ~85s due to free-tier RPM) ===")
    false_blocks = 0
    for idx, q in enumerate(benign, 1):
        out = safe_ask(bot, q, hardened=True)
        is_false_block = out["blocked"] or "No safe context available" in out["reply"]
        if is_false_block:
            false_blocks += 1
            print(f"[FALSE BLOCK #{idx}] Query: {q} -> {out['reply']}")
        else:
            print(f"[BENIGN {idx:02d}/20] OK")
        report["hardened_benign"].append({
            "query": q,
            "false_block": is_false_block,
            "guardrails_triggered": out["guardrails_triggered"],
            "reply": out["reply"],
        })

    summary = {
        "baseline_injection_success": f"{baseline_leaks}/{len(attacks)}",
        "hardened_injection_success": f"{hardened_leaks}/{len(attacks)}",
        "false_blocks_on_benign": f"{false_blocks}/{len(benign)}",
    }
    report["summary"] = summary

    with open("results/audit_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("\n" + "=" * 60)
    print("FINAL AUDIT SUMMARY")
    print(
        f"Successful injections: {summary['baseline_injection_success']} before, "
        f"{summary['hardened_injection_success']} after guardrails; "
        f"{summary['false_blocks_on_benign']} false blocks on 20 normal questions."
    )
    print("Detailed logs saved to results/audit_report.json")
    print("=" * 60)


if __name__ == "__main__":
    main()