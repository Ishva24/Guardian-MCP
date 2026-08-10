# Audit Redaction for MCP Tool Arguments

MCP gateways need useful audit logs without leaking secrets. Audit redaction should preserve tool name, request ID, decision, argument shape, and safe metadata while masking token-like values, key material, credential fields, and large prompt payloads. This keeps incident review possible without turning logs into a second data exposure surface.
