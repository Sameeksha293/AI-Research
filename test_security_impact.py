
from scanner.security_impact_map import generate_security_impact_map

sample_code = """
user_input = input("Enter a command")

result = eval(user_input)

print(result)
"""

result = generate_security_impact_map(sample_code)

print("\n===== SECURITY IMPACT MAP =====")

print("\nINPUT SOURCES:")
for source in result["sources"]:
    print(source)

print("\nSENSITIVE OPERATIONS:")
for sink in result["sinks"]:
    print(sink)

print("\nRISK PATHS:")
for path in result["paths"]:
    print(path)

print("\nSUMMARY:")
print(result.get("summary", result.get("error")))
