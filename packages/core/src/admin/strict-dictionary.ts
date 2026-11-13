// The structured-field rules of the RFC 9421 admin signatures (docs/design/hosting-modes.md 3.2): `Signature-Input`,
// `Signature`, and `Content-Digest` are Dictionaries (RFC 9421 §4.1, §4.2; RFC 9530 §2), parsed by the RFC 9651
// parser of @idp/structured-fields and then held to the one shape the admin Worker accepts. Where RFC 9651 recovers,
// this policy refuses: a repeated key, because a runtime joins a repeated header into one value and the last-wins
// rule would silently pick one signature of two; and a byte sequence that is not canonical base64, so a value compared
// after decoding has exactly one spelling. Dates and Display Strings are refused because the profile never uses them.
import { StructuredFieldError, parseDictionary, type Dictionary, type Parameters, type Recovery } from "@idp/structured-fields";

function refuseUnusedTypes(params: Parameters): void {
  for (const [, value] of params) refuseUnusedType(value.type);
}

function refuseUnusedType(type: string): void {
  if (type === "date" || type === "display-string") throw new StructuredFieldError(`a ${type} is not used by the admin signature profile`);
}

/**
 * Parses a field value as a Dictionary under the admin signature profile's rules.
 *
 * @param input The field value; a repeated field must already be joined with ", " (as Workers' Headers does).
 * @returns The members in order.
 * @throws {StructuredFieldError} The value is not an RFC 9651 Dictionary; is empty; repeats a member or parameter
 *   key; has a byte sequence without canonical padding or with non-zero pad bits; or holds a Date or a Display String.
 */
export function parseStrictDictionary(input: string): Dictionary {
  const recoveries: Recovery[] = [];
  const dictionary = parseDictionary(input, { onRecovery: (recovery) => recoveries.push(recovery) });
  const [recovery] = recoveries;
  if (recovery !== undefined) throw new StructuredFieldError(`${recovery.kind} is refused by the admin signature profile`);
  // RFC 9651 §4.2 fails an empty Dictionary only when the field is required; every field here is.
  if (dictionary.length === 0) throw new StructuredFieldError("empty dictionary");
  for (const [, member] of dictionary) {
    refuseUnusedTypes(member.params);
    for (const item of member.kind === "item" ? [member] : member.items) {
      refuseUnusedType(item.value.type);
      refuseUnusedTypes(item.params);
    }
  }
  return dictionary;
}
