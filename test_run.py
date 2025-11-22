from logic import analyze_input

tests = [
    "http://192.168.1.1/login",
    "https://secure-paypal.com.account.verify-user.net/login",
    "support@secure-mail-paypal-verification.com",
    "hello this is a message, please verify your account immediately",
    "https://xn--pple-43d.com",
    "http://example.com?token=dGhpcyBpcyBiYXNlNjQ=",
]

for t in tests:
    print("\nINPUT:", t)
    result = analyze_input(t)

    print("RISK SCORE:", result["risk_score"])
    print("VERDICT:", result["verdict"])
    print("DETAILS:")
    for d in result["details"]:
        print("-", d)
